import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property int tab:0;property bool sources:false
 property var info:app?app.telemetry.radio:({wifi:[],cell:[],bluetooth:[],errors:[]})
 Row{x:14;y:3;spacing:10
  Repeater{model:["Wi-Fi","4G / 网络","蓝牙"];delegate:ToolButton{text:modelData;width:145;height:39;accent:page.tab===index;onClicked:{page.tab=index;if(app)app.noteAction("radio_tab:"+index);}}}
  ToolButton{text:page.sources?"隐藏来源":"数据来源";width:132;height:39;onClicked:page.sources=!page.sources}
  ToolButton{text:"诊断";width:90;height:39;onClicked:if(app)app.toast((page.info.errors||[]).join("\n")||"读取完成；未提供的高级字段不会补零")}
 }
 InfoList{id:list;x:12;y:49;width:parent.width-24;height:parent.height-54;showSource:page.sources;rows:page.tab===0?(info.wifi||[]):page.tab===1?(info.cell||[]):(info.bluetooth||[])}
 ToolText{anchors.centerIn:parent;text:"正在读取无线电状态…";visible:list.rows.length===0;color:"#a0a2a8"}
}
