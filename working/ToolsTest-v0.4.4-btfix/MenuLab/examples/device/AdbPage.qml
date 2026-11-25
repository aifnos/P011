import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property var info:app?app.telemetry.adb:({})
 ToolText{x:20;y:8;width:740;height:40;text:"保存配置："+(info.saved===1?"开启":info.saved===0?"关闭":"未读取");color:Style.mainColor;font.pixelSize:30}
 ToolText{x:20;y:52;width:740;height:30;text:"adbd 进程："+(info.daemon_running===true?"运行中":info.daemon_running===false?"未观察到":"未知")+"    "+(info.changed_by_trial?"配置已修改，退出试验恢复原值":"配置未改动");font.pixelSize:22}
 Row{x:20;y:98;spacing:12
  ToolButton{text:"保存开启";width:180;accent:true;enabled:app&&app.online;onClicked:app.confirm("保存 ADB 开启配置，不再输入工程密码。\n本轮不重启、不重新枚举 USB；退出试验会恢复原值。",function(){app.action("adb_on");},0)}
  ToolButton{text:"保存关闭";width:180;danger:true;enabled:app&&app.online;onClicked:app.confirm("将下次启动的 ADB 配置设为关闭。\n当前连接不会立即断开；请勿在试验期间重启。结束时恢复原值，避免失去维护入口。",function(){app.action("adb_off");},3)}
  ToolButton{text:"恢复原配置";width:200;enabled:app&&app.online;onClicked:app.action("adb_restore")}
 }
 ToolText{x:20;y:157;width:parent.width-40;height:47;text:"这是配置开关测试，不是热切换。测试版不提供立即重启；不会自动关闭当前调试连接。";font.pixelSize:19;color:"#a5a7ae";wrapMode:Text.Wrap;elide:Text.ElideNone}
}
