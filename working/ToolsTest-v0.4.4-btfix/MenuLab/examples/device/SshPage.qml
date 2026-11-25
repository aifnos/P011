import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property var info:app?app.telemetry.ssh:({})
 ToolText{x:18;y:4;width:740;height:40;text:info.running?"SSH 已开启 · "+info.bind+":2222 · 剩余 "+info.remaining+" 秒":"SSH 已关闭";font.pixelSize:27;color:Style.mainColor}
 ToolText{x:18;y:45;width:750;height:30;text:info.public_key_supplied?"电脑公钥已就绪 · 仅密钥认证 · 最长 5 分钟 · root 登录":"未配置电脑公钥：查看启动日志中的 SSH_KEY 提示";font.pixelSize:20;color:info.public_key_supplied?"#b3b5bd":Style.subColor}
 Row{x:18;y:85;spacing:10
  ToolButton{text:"开启 USB SSH";width:186;accent:true;enabled:app&&app.online&&info.public_key_supplied&&!info.running;onClicked:app.confirm("仅监听学习笔的 127.0.0.1:2222，不开放局域网。\n开启后在电脑双击 SSH-USB.cmd。root 公钥认证，5 分钟或试验结束时关闭。",function(){app.action("ssh_usb");},0)}
  ToolButton{text:"开启 Wi-Fi SSH";width:196;enabled:app&&app.online&&info.public_key_supplied&&!info.running;onClicked:app.confirm("只绑定当前 Wi-Fi 私网 IPv4，不绑定 4G 或所有地址。\n这会在局域网开放 root 公钥登录，最长 5 分钟。请只在可信网络测试，不使用公共 Wi-Fi。",function(){app.action("ssh_wifi");},3)}
  ToolButton{text:"关闭 SSH";width:152;danger:true;enabled:app&&app.online&&info.running;onClicked:app.confirm("关闭本次试验启动的 SSH，并结束已识别的登录会话。\n不停止原有的其他 SSH 服务。",function(){app.action("ssh_stop");},0)}
  ToolButton{text:"连接说明";width:150;onClicked:app.toast("电脑双击 SSH-USB.cmd / SSH-LAN.cmd；私钥保存在 D:\\project\\P011\\keys，不上传私钥。")}
 }
 ToolText{x:18;y:140;width:parent.width-36;height:62;text:info.error?info.error:(info.host_fingerprint?("主机指纹："+info.host_fingerprint):"仅管理本次实例，不自启、不改系统密码。监听成功不等于已经登录成功。");font.pixelSize:17;color:info.error?Style.subColor:"#999ca6";wrapMode:Text.WrapAnywhere;elide:Text.ElideNone}
}
