import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item {
 id:page
 property var app:null
 property int tab:0
 property bool sources:false
 property int btResultSignals:0
 property int btNamedSignals:0
 property int btPairedSignals:0
 property int lastObserved:-1
 property var info:app?app.telemetry.radio:({wifi:[],cell:[],bluetooth:[],errors:[]})
 property var btRows:discoveryRows(discovery.snapshot)
 function statusText(s) {
  if(!s.available)return s.error?"服务不可用："+s.error:"正在读取";
  if(!s.powered)return "蓝牙未开启，请在原厂设置开启";
  if(s.status==="starting")return "正在开始本轮搜索";
  if(s.active)return "本轮搜索中 · 剩余 "+Math.ceil(Number(s.remaining_ms||0)/1000)+" 秒";
  if(s.status==="error")return "搜索失败："+s.error;
  if(s.status==="completed")return "本轮搜索完成"+(s.discovering?"；系统扫描仍在继续":"");
  if(s.status==="stopped")return "本轮搜索已停止";
  return "点击搜索，观察附近设备";
 }
 function row(key,value,note) {return {key:key,value:String(value),available:true,source:"BlueZ 实时发现会话",note:note||""};}
 function discoveryRows(s) {
  var counts=s.counts||{}, rows=[row("搜索状态",statusText(s)),row("本轮收到更新",Number(counts.observed||0),"仅统计本次会话新增/属性更新，不把启动缓存算成新发现"),row("已知设备",Number(counts.total||0)+" · 具名 "+Number(counts.named||0),"列表显示最多 100 项，优先本轮及具名设备"),row("原厂音频结果信号",btResultSignals+" / 具名 "+btNamedSignals+" / 已配对 "+btPairedSignals,"原厂有设备类型筛选；通用发现不依赖此计数")];
  if(s.storage_limited)rows.push(row("结果存储达到上限","当前保留最多 1500 项","以上计数仅覆盖已保留对象，不代表环境全部设备"));
  var devices=s.devices||[];
  for(var i=0;i<devices.length;i++){
   var d=devices[i],name=d.named?d.name:"未命名设备",key=d.seen_this_session?"本轮发现":"历史缓存";
   rows.push(row(key,name+" · "+d.address,(d.seen_this_session?"本轮收到新增/更新事件":"已有对象，未证实本轮再次出现")+"；仅查看，不配对或连接"));
  }
  rows.push(row("搜索范围","经典蓝牙 / 低功耗蓝牙","设备必须按其支持方式广播；开着蓝牙不一定处于可发现状态。停止仅释放本页会话。"));
  return rows;
 }
 function beginSearch(){discovery.start();if(app)app.noteAction("radio_bluez_search_request");}
 function prepareLeave(){discovery.stop();}
 onTabChanged:{if(tab!==2)discovery.stop();else discovery.refresh();}
 BtDiscovery {
  id:discovery;owner:"toolbox"
  onNotice:if(app)app.toast(message)
  onUpdated:{
   var n=Number(snapshot.counts&&snapshot.counts.observed||0);
   if(page.tab===2&&n!==page.lastObserved){page.lastObserved=n;if(app)app.mark("radio_bluez_observed:"+n+":status="+snapshot.status);}
  }
 }
 Row {x:14;y:3;spacing:8
  Repeater {model:["Wi-Fi","4G / 网络","蓝牙"];delegate:ToolButton {text:modelData;width:118;height:39;accent:page.tab===index;onClicked:{page.tab=index;if(app)app.noteAction("radio_tab:"+index);}}}
  ToolButton {text:page.sources?"隐藏来源":"数据来源";width:112;height:39;onClicked:page.sources=!page.sources}
  ToolButton {text:page.tab===2?(discovery.snapshot.active?"停止本轮":"搜索 20 秒"):"诊断";width:136;height:39;onClicked:{if(page.tab===2){if(discovery.snapshot.active){discovery.stop();if(app)app.noteAction("radio_bluez_search_stop");}else page.beginSearch();}else if(app)app.toast((page.info.errors||[]).join("\n")||"读取完成");}}
 }
 Connections {target:typeof engineSocket!=="undefined"?engineSocket:null;ignoreUnknownSignals:true;onSig_btScaned:{page.btResultSignals++;if(ssid&&String(ssid).length>0)page.btNamedSignals++;if(paired)page.btPairedSignals++;}}
 InfoList {id:list;x:12;y:49;width:parent.width-24;height:parent.height-54;showSource:page.sources;rows:page.tab===0?(info.wifi||[]):page.tab===1?(info.cell||[]):page.btRows}
 ToolText {anchors.centerIn:parent;text:"正在读取无线电状态…";visible:list.rows.length===0;color:"#a0a2a8"}
}
