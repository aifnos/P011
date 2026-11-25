import QtQuick 2.10
import "Api.js" as Api
import BtManager.BtStatusDefine 1.0
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property int tab:0;property bool sources:false;property bool scanStarted:false;property int btResultSignals:0;property int btNamedSignals:0;property int btPairedSignals:0
 property bool replayUsed:false;property bool replayBusy:false;property var replayRequest:null;property int replaySerial:0
 property var info:app?app.telemetry.radio:({wifi:[],cell:[],bluetooth:[],errors:[]})
 property var btRows:[{key:"原厂结果信号（本页）",value:"总 "+btResultSignals+" / 具名 "+btNamedSignals+" / 已配对 "+btPairedSignals,available:true,source:"engineSocket.sig_btScaned",note:"只计数，不记录设备名称或地址"}].concat(info.bluetooth||[])
 function bluezScanState(){var age=Date.now()/1000-Number(info.epoch||0);if(!info.epoch||age<0||age>3)return "unknown";var rows=info.bluetooth||[];for(var i=0;i<rows.length;i++)if(rows[i].key==="蓝牙扫描中")return rows[i].value==="是"?"busy":"idle";return "unknown";}
 function stopBtScan(){scanStop.stop();if(!scanStarted)return;scanStarted=false;if(typeof engineSocket!=="undefined")try{engineSocket.sendBtScan(false);if(app)app.noteAction("radio_bt_scan_stop");}catch(e){if(app)app.toast("停止搜索请求失败："+e);}}
 function startBtScan(){var state=bluezScanState();if(state!=="idle"){if(app)app.toast(state==="busy"?"原厂扫描已在进行；请先结束原厂扫描后重试":"蓝牙扫描状态未及时确认；请等状态刷新后重试");return;}if(typeof engineSocket==="undefined"||typeof btManager==="undefined"){if(app)app.toast("原厂蓝牙控制服务不可用");return;}if(btManager.getStatus()===BtConnectStatus.Bt_Close){if(app)app.toast("请先在原厂设置开启蓝牙");return;}try{engineSocket.sendBtScan(true);}catch(e){if(app)app.toast("搜索请求失败："+e);return;}scanStarted=true;scanStop.restart();if(app){app.noteAction("radio_bt_scan_start");app.toast("已请求搜索；请看扫描状态和已知设备列表");}}
 function cancelCacheReplay(){replaySerial++;replayTimeout.stop();var pending=replayRequest;replayRequest=null;replayBusy=false;if(pending)try{pending.abort();}catch(e){}}
 function replayBtCache(){
  if(replayUsed||replayBusy||tab!==2)return;
  if(scanStarted){if(app)app.toast("请等待本页搜索结束后再重发结果");return;}
  if(typeof engineSocket==="undefined"||typeof engineSocket.sig_btScaned!=="function"){if(app)app.toast("原厂结果监听不可用");return;}
  var serial=++replaySerial,requestedAt=Date.now();replayBusy=true;replayTimeout.restart();
  replayRequest=Api.request("/api/bt-state",null,function(ok,d){
   if(serial!==page.replaySerial||page.tab!==2)return;
   page.replayBusy=false;page.replayRequest=null;replayTimeout.stop();
   var now=Date.now(),age=now/1000-Number(d&&d.epoch),elapsed=now-requestedAt;
   if(!ok||!d||d.available!==true||d.powered!==true||d.discovering!==true||!isFinite(age)||age<0||age>2||elapsed<0||elapsed>2000){if(app){app.mark("radio_bt_cache_replay_skipped:state_unconfirmed");app.toast("当前扫描状态未及时确认，未重发");}return;}
   if(page.replayUsed||page.scanStarted||typeof engineSocket==="undefined"||typeof engineSocket.sig_btScaned!=="function"){if(app)app.toast("结果重发条件已变化");return;}
   // Borrow the existing scan only for one cache replay; never claim or stop it.
   page.replayUsed=true;if(app)app.noteAction("radio_bt_cache_replay_request");
   try{engineSocket.sendBtScan(true);if(app)app.toast("已请求重发结果，请观察信号计数");}
   catch(e){if(app){app.mark("radio_bt_cache_replay_error");app.toast("结果重发请求失败");}}
  });
 }
 function prepareLeave(){cancelCacheReplay();stopBtScan();}
 onTabChanged:if(tab!==2){cancelCacheReplay();stopBtScan();}
 Row{x:14;y:3;spacing:8
  Repeater{model:["Wi-Fi","4G / 网络","蓝牙"];delegate:ToolButton{text:modelData;width:118;height:39;accent:page.tab===index;onClicked:{page.tab=index;if(app)app.noteAction("radio_tab:"+index);}}}
  ToolButton{text:page.sources?"隐藏来源":"数据来源";width:112;height:39;onClicked:page.sources=!page.sources}
  ToolButton{text:page.tab===2?(page.scanStarted?"已请求":"搜索"):"诊断";width:88;height:39;onClicked:{if(page.tab===2){if(!page.scanStarted)page.startBtScan();}else if(app)app.toast((page.info.errors||[]).join("\n")||"读取完成；未提供的高级字段不会补零")}}
  ToolButton{text:page.replayBusy?"检查中":page.replayUsed?"已请求重发":"结果重发";visible:page.tab===2;width:132;height:39;onClicked:page.replayBtCache()}
 }
 Timer{id:replayTimeout;interval:2500;onTriggered:{page.cancelCacheReplay();if(app){app.mark("radio_bt_cache_replay_skipped:timeout");app.toast("扫描状态读取超时，未重发");}}}
 Timer{id:scanStop;interval:20000;onTriggered:page.stopBtScan()}
 Timer{interval:5000;repeat:true;running:page.tab===2;onTriggered:if(app)app.mark("radio_bt_signal_counts:total="+page.btResultSignals+":named="+page.btNamedSignals+":paired="+page.btPairedSignals)}
 Connections{target:typeof engineSocket!=="undefined"?engineSocket:null;ignoreUnknownSignals:true;onSig_btScaned:{page.btResultSignals++;if(ssid&&String(ssid).length>0)page.btNamedSignals++;if(paired)page.btPairedSignals++;}}
 InfoList{id:list;x:12;y:49;width:parent.width-24;height:parent.height-54;showSource:page.sources;rows:page.tab===0?(info.wifi||[]):page.tab===1?(info.cell||[]):page.btRows}
 ToolText{anchors.centerIn:parent;text:"正在读取无线电状态…";visible:list.rows.length===0;color:"#a0a2a8"}
 Component.onCompleted:if(app)app.mark("radio_bt_signal_type:"+(typeof engineSocket!=="undefined"?typeof engineSocket.sig_btScaned:"no_engine"))
 Component.onDestruction:{cancelCacheReplay();stopBtScan();}
}
