import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property var info:app?app.telemetry.battery:({rows:[],history:[]});property bool details:false
 function val(v,u){return v===null||v===undefined?"—":v+u;}
 Row{x:14;y:4;spacing:9
  ToolButton{text:page.details?"概览 / 曲线":"详细字段";width:156;height:38;onClicked:page.details=!page.details}
  ToolText{width:610;height:38;text:(info.node||"读取中")+" · "+(info.status||"未知")+" · 仅记录真实字段";font.pixelSize:19;color:"#a8a9ae"}
 }
 Row{x:20;y:48;spacing:22;visible:!page.details
  Column{width:190;spacing:5
   ToolText{text:page.val(info.capacity,"%");font.pixelSize:46;color:Style.mainColor;height:52}
   ToolText{text:"电压 "+page.val(info.voltage," V");font.pixelSize:22}
   ToolText{text:"电流 "+page.val(info.current," mA");font.pixelSize:22}
   ToolText{text:"温度 "+page.val(info.temperature," °C");font.pixelSize:22}
  }
  Column{spacing:6;width:550
   Row{spacing:6
    ToolButton{text:"电压";width:86;height:34;accent:chart.metric==="voltage";onClicked:chart.metric="voltage"}
    ToolButton{text:"电流";width:86;height:34;accent:chart.metric==="current";onClicked:chart.metric="current"}
    ToolButton{text:"温度";width:86;height:34;accent:chart.metric==="temperature";onClicked:chart.metric="temperature"}
    ToolText{text:"最近 120 个样本";font.pixelSize:17;height:34;width:190;color:"#a0a2a8"}
   }
   Trend{id:chart;width:540;height:86;points:page.info.history||[]}
   ToolText{text:"曲线自动缩放；电池侧电流 / 功率不等于 USB 输入。";font.pixelSize:17;width:540;color:"#a0a2a8"}
  }
 }
 InfoList{x:10;y:48;width:parent.width-20;height:parent.height-53;rows:info.rows||[];visible:page.details;showSource:true}
}
