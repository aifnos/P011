import QtQuick 2.0
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import "../Funcs/UILogics.js" as UILogic
import "../ZybControls/"
import "./"
import "../Style"
import "../Global"
import "../ZybStore"
import DevConnection.StatusDefine 1.0
import BtManager.BtStatusDefine 1.0
import com.zyb.PingDefine 1.0
import "file:///mnt/data/p011-menu" as Toolbox
import "file:///mnt/data/p011-menu/BtMerge.js" as BtMerge

Rectangle {
id:btInfo
property string curBtMac : btManager.getLastConnBtMac()
property string curBtSsid : ""
property bool isConnecting : false
property int curConnectIndex : 0
property string strPaired: qsTr("已配对")
property string strNotPaired: qsTr("可用设备")
property bool isConnectedItem : false
property bool pageAlive: true
property bool btEnabled: btManager.getStatus() !== BtConnectStatus.Bt_Close
property bool discoveryStarted: false
property string strFound: qsTr("本轮发现（仅查看）")
property string strCache: qsTr("历史缓存（仅查看）")
signal backToParent();
signal btConnected();

color: Style.mainbgColor

Toolbox.BtDiscovery {
id: discovery
owner: "stock"
onUpdated: btInfo.mergeDiscovery(snapshot)
}

function ensurePlaceholder() {
if(isHaveItem("") < 0)
btmodel.append({group:strNotPaired,ssid:"",mac:"",state:"",discoveryOnly:false});
}

function stopDiscovery() {
initTimer.stop();
discoveryStarted = false;
discovery.stop();
}

function startDiscovery() {
if(!pageAlive || !btEnabled || discoveryStarted) return;
discoveryStarted = true;
discovery.start();
}

function mergeDiscovery(snapshot) {
if(!pageAlive || !btEnabled || btInfo.state === "close" || !snapshot || snapshot.powered !== true) return;
BtMerge.merge(snapshot, btmodel, strFound, strCache, qsTr("未命名设备"));
}

function acceptStockResult(mac, ssid, paired) {
if(!pageAlive || !btEnabled || btInfo.state === "close") return;
btInfo.state = "scanResult";
var status = "normal";
var sgroup = paired ? strPaired : strNotPaired;
var vindex = isHaveItem(mac);
if(vindex < 0) {
if(sgroup === strPaired) {
var count = getPairedItemCount();
if(mac === btManager.getLastConnBtMac() && btManager.getStatus() === BtConnectStatus.Bt_Connected)
status = "connected";
btmodel.insert(count,{group:sgroup,ssid:ssid,mac:mac,state:status,discoveryOnly:false});
} else {
btmodel.append({group:sgroup,ssid:ssid,mac:mac,state:status,discoveryOnly:false});
}
btMacList.push(mac);
} else {
var row = btmodel.get(vindex);
if(ssid.length) row.ssid = ssid;
row.group = sgroup;
row.discoveryOnly = false;
}
}



function getCurStatus()
{
switch(btManager.getStatus())
{
case BtConnectStatus.Bt_Close:
return "close"
case BtConnectStatus.Bt_Scaning:
return "scaning"
case BtConnectStatus.Bt_Connecting:
return "connecting"
}
}

state: btManager.getStatus() === BtConnectStatus.Bt_Close ? "close":"scaning"

states: [
State {
name: "close"
},
State {
name: "scaning"
},

State {
name: "connecting"
},

State {
name: "scanResult"
},

State {
name: "scanNoResult"
}
]


ZybText
{
id:noResulttext
text: qsTr("通信范围内没有搜索到蓝牙设备")
font.pixelSize: Style.tipFontPixel
anchors.centerIn: parent

visible: btInfo.state === "scanNoResult"
}

Timer
{
id:connectTimer
onTriggered:
{
if(btManager.getStatus() === BtConnectStatus.Bt_Connecting)
{
btManager.setStatus(BtConnectStatus.Bt_UnKown);
}
}
}

function connectToSsid(mac)
{
btManager.setStatus(BtConnectStatus.Bt_Connecting);
resetStatus();
view.model.get(view.currentIndex).state = "connecting";
console.log("connectToBtSsid =",mac);
engineSocket.sendBtConnect(mac);
connectTimer.start();
}

PopupDialog
{
id:ignoreDig
x:devManager.isLeftHand?(parent.width - (parent.width - width)/2):((parent.width - width) / 2)
y:devManager.isLeftHand?(parent.height-(parent.height - height) / 2):((parent.height - height) / 2)
isVertical:false
btnWidth : 150
closeBtnVisible:true
onLeftClicked:
{
ignoreDig.close();
if(isConnectedItem)
{
engineSocket.sendBtDisconnect();
}
else
{
connectToSsid(curBtMac);
}
}

onRightClicked:
{
ignoreDig.close();
engineSocket.sendBtIgnore(curBtMac);

}
}


PopupDialog
{
id:errDig
width: 580
height: 220
x:devManager.isLeftHand?(parent.width - (parent.width - width)/2):((parent.width - width) / 2)
y:devManager.isLeftHand?(parent.height-(parent.height - height) / 2):((parent.height - height) / 2)
isVertical:false
btnWidth : 120
closeBtnVisible:false
content2Visible:true
leftTxtVisble: false
titleFontBold: true
content: qsTr("蓝牙配对失败")
content2: qsTr("请确定“") + curBtSsid +"”" +qsTr("已打开而且在通信范围内。")
rightTxt: qsTr("好")


onRightClicked:
{
errDig.close();
}
}

ListModel {
id:btmodel
}

ListView {
id:view
focus: true
anchors.fill: parent
clip: true
spacing: 10
topMargin: 10
anchors.left: parent.left
anchors.leftMargin: 10
anchors.right: parent.right
anchors.rightMargin: 10
visible: view.contentHeight > 0
header:Item {
id: header
width: parent.width
height: 65
ZybBackButton{
id:backButton
anchors.top: parent.top
anchors.left: parent.left

onBackClicked: {
pageAlive = false;
stopDiscovery();
if(btManager.getStatus() !== BtConnectStatus.Bt_Close)
{
console.log("sendBtScan(false)");
engineSocket.sendBtScan(false);
}
UILogic.backToSetPage();
}

}


ZybText {
id: title
text: qsTr("蓝牙")
font.styleName: "Bold"
anchors.horizontalCenter: parent.horizontalCenter
anchors.verticalCenter: backButton.verticalCenter
}

BasicSwitchButton
{
id:btswitchButton
anchors.right: parent.right
anchors.verticalCenter: backButton.verticalCenter
state: btManager.getStatus() !== BtConnectStatus.Bt_Close ? "on":"off"
onModelChanged:
{
if(mode === true)
{
btEnabled = true;
engineSocket.sendBtOn();
btInfo.state = "scaning";

}
else
{
btEnabled = false;
stopDiscovery();
btInfo.state = "close";
engineSocket.sendBtOff();
btManager.setIsReOpen(true);
view.model.clear();
btmodel.clear();
}

}
}

Toolbox.ToolButton {
text: discovery.snapshot.active ? qsTr("搜索中") : qsTr("搜索")
width: 100; height: 44
anchors.right: btswitchButton.left
anchors.rightMargin: 40
anchors.verticalCenter: backButton.verticalCenter
enabled: pageAlive && btEnabled && !discovery.snapshot.active
onClicked: { discoveryStarted = false; startDiscovery(); }
}

onVisibleChanged: {
if(visible){
btswitchButton.state = btManager.getStatus() !== BtConnectStatus.Bt_Close ? "on":"off"
}
}

Connections
{
target: engineSocket
onSig_btOn:
{
if(!res)
{
btEnabled = false;
stopDiscovery();
btswitchButton.state = "off";
main.showTip(qsTr("打开蓝牙失败"));
}
}
}
}

section{
property: "group"
criteria: ViewSection.FullString
delegate: Rectangle{
width: ListView.view.width
height: 70
color: "transparent"
radius: 6
Text {
id: groupText
anchors.verticalCenter: parent.verticalCenter
anchors.left: parent.left
anchors.leftMargin: 0
font.pixelSize: 24
color: "#999999"
text: section //对应section.property指定的字段
}

RotationImage
{
id: imgRefresh
source: "qrc:/images/connecting56x56.png"
running: visible
anchors.left: groupText.right
anchors.leftMargin: 30
anchors.verticalCenter: groupText.verticalCenter
duration: 1000
visible: section === strNotPaired
}

}
labelPositioning: ViewSection.InlineLabels
}

model: btmodel
delegate: Rectangle {
id:control
width: parent.width
height: (model.ssid.length > 0) ?70:0
radius: 6
state: model.state
color: mouse.pressed ? Qt.darker("#993C3D42") : "#993C3D42"
ZybText {
id: ltext
font.styleName: "Bold"
text: model.ssid
anchors.left: parent.left
anchors.leftMargin: 33
anchors.verticalCenter: parent.verticalCenter
visible: model.ssid.length > 0
}

ZybText {
id: rtext
text: qsTr("连接中")
color: "#FFFFFF"
visible: control.state === "connecting" && model.ssid.length > 0
anchors.right: imgLoading.left
anchors.rightMargin: 9
anchors.verticalCenter: parent.verticalCenter
}

ZybText {
id: rtext2
text: qsTr("未连接")
color: "#FFFFFF"
visible: control.state === "normal" && model.group === strPaired  && model.ssid.length > 0
anchors.right: parent.right
anchors.rightMargin: 20
anchors.verticalCenter: parent.verticalCenter
}

RotationImage
{
id: imgLoading
source: "qrc:/images/connecting56x56.png"
running: visible===true
duration: 1000
visible: control.state === "connecting"  && model.ssid.length > 0

anchors.right: parent.right
anchors.rightMargin: 33
anchors.verticalCenter: parent.verticalCenter
}


Image {
id: imgStatus
fillMode: Image.PreserveAspectFit
clip: true
source: "qrc:/images/wifi_set_connected.png"
visible: control.state === "connected"  && model.ssid.length > 0
anchors.right: parent.right
anchors.rightMargin: 33
anchors.verticalCenter: parent.verticalCenter
}

MouseArea {
id:mouse
anchors.fill: parent
onClicked:
{
if(model.discoveryOnly) {
main.showTip(qsTr("仅显示发现结果，未确认音频兼容，不发起配对"));
return;
}
view.currentIndex = index
console.log(index,model.ssid);
if(btManager.getStatus() === BtConnectStatus.Bt_Connecting)
{
main.showTip(qsTr("蓝牙正在配对中...,请稍等"))
return;
}

curBtMac = model.mac;
curBtSsid = model.ssid;

if(btManager.getStatus()=== BtConnectStatus.Bt_Connected)
{
if(btManager.getLastConnBtMac() === curBtMac) //断开
{
isConnectedItem = true
ignoreDig.leftTxt = qsTr("断开连接")
ignoreDig.rightTxt = qsTr("忽略此设备")
ignoreDig.content = model.ssid;
ignoreDig.open();
}
else    //忽略
{
if(model.group === strPaired)
{
isConnectedItem = false
ignoreDig.leftTxt = qsTr("连接此设备")
ignoreDig.rightTxt = qsTr("忽略此设备")
ignoreDig.content = model.ssid
ignoreDig.open();
}
else
{
connectToSsid(model.mac);
}


}
}
else
{
if(model.group === strPaired)
{
isConnectedItem = false
ignoreDig.leftTxt = qsTr("连接此设备")
ignoreDig.rightTxt = qsTr("忽略此设备")
ignoreDig.content = model.ssid
ignoreDig.open();
}
else
{
connectToSsid(model.mac);
}
}
}
}
}

ScrollIndicator.vertical: ScrollIndicator { }
}

function isPairedItem(index)
{
return  view.model.get(index).group === strPaired
}

function getPairedItemCount()
{
var c=0;
for(var i=0;i<view.model.count;i++)
{
if(view.model.get(i).group === strPaired)
c++;
}

return c;
}

function disconnected()
{
for(var i=0;i<view.model.count;i++)
{
if(view.model.get(i).state === "connected")
{
view.model.get(i).state ="normal";
break;
}
}

}

function resetStatus()
{
for(var i=0;i<view.model.count;i++)
{
view.model.get(i).state = "normal"
}
}

function initStatusExcep(row)
{
for(var i=0;i<view.model.count;i++)
{
if(i !== row)
view.model.get(i).state = "normal"
}
}

function getConnectModelIndex()
{
for(var i=0;i<view.model.count;i++)
{
if(view.model.get(i).mac === btManager.getLastConnBtMac())
return i;
}
return -1;
}

function isHaveItem(mac)
{
for(var i=0;i<view.model.count;i++)
{
if(String(view.model.get(i).mac).toUpperCase() === String(mac).toUpperCase())
return i;
}

return -1;
}

function removeItem(mac)
{
var index = btMacList.indexOf(mac);
if(index >= 0) btMacList.splice(index,1);
for(var i=0;i<view.model.count;i++)
{
if(view.model.get(i).mac === mac )
{
console.log("removeItem",view.model.get(i).ssid);
view.model.remove(i);
break;
}
}
}

function updateConnectedItem()
{
resetStatus();
var have = false;

for(var i=0;i<view.model.count;i++)
{
if(view.model.get(i).mac === btManager.getLastConnBtMac())
{
console.log("update connected item",i,btManager.getLastConnBtMac() );
if(view.model.get(i).group === strPaired )
{
view.model.get(i).state = "connected"
}
else
{
view.model.get(i).group = strPaired;
view.model.get(i).state = "connected"
}


have = true;

if(i !== 0)
{
console.log("move connected item to top");
btmodel.move(i,0,1);
}
}
}

if(have === false)
{
addFirstConnectedItem();
}

}

function addFirstConnectedItem()
{
var mac = btManager.getLastConnBtMac();
var ssid = btManager.getLastConnBtSsid();
if(mac === "" || isHaveItem(mac) >= 0)
return;

btmodel.insert(0,{group: strPaired,"ssid":ssid,"mac":mac,"state":"connected",discoveryOnly:false});
}

property var btMacList: []

Connections
{
target: engineSocket
onSig_btError:
{
main.showTip(err);
}

onSig_btOn:
{
if(res)
{
if(!pageAlive || !btEnabled) return;
btMacList = [];
btInfo.state = "scaning"
ensurePlaceholder();
if(!discoveryStarted) { initTimer.interval = 250; initTimer.restart(); }
}
else
{
}
}

onSig_btOff:
{
btEnabled = false;
stopDiscovery();
btInfo.state = "close";
btMacList = [];
view.model.clear();
btmodel.clear();
}


onSig_btScaned: //
{
acceptStockResult(mac, ssid, paired);
}

onSig_btRemoved:
{
removeItem(mac);
}

onSig_btDisconnect: //val
{
console.log("onSig_btDisconnect",val);
resetStatus();
connectTimer.stop();
}

onSig_btDisconnectFailed:
{
main.showTip(qsTr("断开蓝牙设备失败"));
connectTimer.stop();
}

onSig_btConnected:
{
connectTimer.stop();
if(btManager.getStatus() === BtConnectStatus.Bt_Close)
{
return;
}

console.log("onSig_BTConnected");
updateConnectedItem();
btConnected();

pingManager.addPingData(PingDefine.PING_EVENT_SET_BT_CONNECT);
}

onSig_btConnectFailed:
{
connectTimer.stop();
if(btManager.getStatus() === BtConnectStatus.Bt_Close)
{
return;
}

console.log("onSig_BTConnectFailed");
resetStatus();
errDig.open();
}

onSig_btStatusChanged:
{
connectTimer.stop();
if(sta === 1)
{
disconnected();
}
}

onSig_btIgnore:
{
removeItem(mac);
}

}

Timer
{
id:initTimer
repeat: false
running: false
interval: 30
onTriggered:
{
console.log("bt initTimer ",btManager.getStatus(),BtConnectStatus.Bt_Close)
if(pageAlive && btEnabled && !discoveryStarted)
{
ensurePlaceholder();
engineSocket.sendBtScan(true);
startDiscovery();
if(btManager.getStatus() === BtConnectStatus.Bt_Connected)
{
addFirstConnectedItem();
}
}
}
}

Component.onCompleted:
{
initTimer.start();
}

Component.onDestruction:
{
pageAlive = false;
stopDiscovery();
console.log("bt page Component.onDestruction")
btmodel.clear();
}
}
