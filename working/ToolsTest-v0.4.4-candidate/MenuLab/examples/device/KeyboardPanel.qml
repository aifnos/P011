import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Rectangle {
    id:kb;color:Style.mainbgColor;visible:false;property string value:"";property bool symbols:false
    signal accepted(string value);signal cancelled()
    function show(v){value=v;symbols=false;visible=true;forceActiveFocus();}
    MouseArea{anchors.fill:parent}
    Rectangle{x:10;y:5;width:parent.width-220;height:40;radius:5;color:"#282a2e";ToolText{anchors.fill:parent;anchors.margins:6;text:kb.value||"输入网址";font.pixelSize:21;elide:Text.ElideLeft}}
    ToolButton{x:parent.width-204;y:5;width:94;height:40;text:"取消";onClicked:{kb.visible=false;kb.cancelled();}}
    ToolButton{x:parent.width-104;y:5;width:94;height:40;text:"访问";accent:true;onClicked:{kb.visible=false;kb.accepted(kb.value);}}
    Column{x:10;y:53;spacing:5
        Repeater{model:kb.symbols?["1234567890","-_:/.?=&%#","@+~!$(),;*"]:["qwertyuiop","asdfghjkl","zxcvbnm"]
            delegate:Row{spacing:5;property string letters:modelData
                Repeater{model:parent.letters.split("");delegate:ToolButton{width:(kb.width-65)/10;height:44;text:modelData;onClicked:if(kb.value.length<2048)kb.value+=text}}
            }
        }
    }
    Row{x:10;y:202;spacing:6
        ToolButton{width:108;height:46;text:kb.symbols?"ABC":"123 / ?";onClicked:kb.symbols=!kb.symbols}
        ToolButton{width:104;height:46;text:"https://";onClicked:kb.value+="https://"}
        ToolButton{width:82;height:46;text:".com";onClicked:kb.value+=".com"}
        ToolButton{width:74;height:46;text:".cn";onClicked:kb.value+=".cn"}
        ToolButton{width:70;height:46;text:"/";onClicked:kb.value+="/"}
        ToolButton{width:90;height:46;text:"清空";onClicked:kb.value=""}
        ToolButton{width:120;height:46;text:"退格";onClicked:kb.value=kb.value.slice(0,-1)}
    }
    Keys.onPressed:{
        if(event.key===Qt.Key_Backspace)value=value.slice(0,-1);
        else if(event.key===Qt.Key_Return||event.key===Qt.Key_Enter){visible=false;accepted(value);}
        else if(event.key===Qt.Key_Escape){visible=false;cancelled();}
        else if(event.text&&value.length<2048)value+=event.text;event.accepted=true;
    }
}
