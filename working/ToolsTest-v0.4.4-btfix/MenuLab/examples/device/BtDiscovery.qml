import QtQuick 2.10
import "Api.js" as Api

Item {
    id: client
    visible: false
    width: 0; height: 0
    property string owner: "toolbox"
    property var snapshot: ({available:false,powered:false,discovering:false,status:"idle",active:false,devices:[],counts:{total:0,named:0,observed:0},error:""})
    property string requestId: ""
    property bool alive: true
    property bool busy: false
    property int serial: 0
    property int sequence: 0
    property double lastStartAt: 0
    property var pending: null
    property var controlRequest: null
    property string lastMark: ""
    property var lifetime: ({alive:true})
    signal updated()
    signal notice(string message)
    function announce(message) {
        notice(message);
        if(owner==="stock"&&typeof main!=="undefined")main.showTip(message);
    }
    function cancelPoll() {
        serial++; watchdog.stop(); busy=false;
        var old=pending;pending=null;
        if(old)try{old.abort();}catch(e){}
    }
    function applySnapshot(data) {
        if(!alive||!data)return;
        if(!requestId||data.owner!==owner||data.request_id!==requestId){
            var cached={};for(var key in data)cached[key]=data[key];
            cached.active=false;cached.status="idle";cached.remaining_ms=0;
            cached.counts={total:data.counts&&data.counts.total||0,named:data.counts&&data.counts.named||0,observed:0};
            cached.devices=[];
            var previous=data.devices||[];
            for(var i=0;i<previous.length;i++){var item={};for(var field in previous[i])item[field]=previous[i][field];item.seen_this_session=false;item.source="cache";cached.devices.push(item);}
            data=cached;
        }
        snapshot=data;
        var mark="owner="+owner+":g="+data.generation+":status="+data.status+":observed="+Number(data.counts&&data.counts.observed||0)+":rows="+(data.devices||[]).length;
        if(mark!==lastMark){lastMark=mark;console.log("P011_BT_UI|"+Date.now()+"|"+mark);if(data.status==="error"&&data.powered&&data.owner===owner)announce("蓝牙搜索失败："+data.error);}
        updated();
    }
    function refresh() {
        if(!alive||busy)return;
        busy=true;var ticket=++serial,life=lifetime;watchdog.restart();
        pending=Api.request("/api/bt",null,function(ok,data){
            if(!life.alive||ticket!==client.serial)return;
            client.pending=null;client.busy=false;watchdog.stop();
            if(ok)client.applySnapshot(data);
            else client.announce("蓝牙状态读取失败");
        });
    }
    function start() {
        if(!alive)return;
        // Repeated entry/on callbacks reuse the same in-flight owned session.
        if(requestId&&(Date.now()-lastStartAt<3000||(snapshot.active&&snapshot.owner===owner&&snapshot.request_id===requestId)))return;
        cancelPoll();sequence++;lastStartAt=Date.now();requestId="r"+String(lastStartAt)+String(sequence);
        var ticket=serial,id=requestId,life=lifetime;
        controlRequest=Api.request("/api/action","bt_start:"+owner+":"+id,function(ok,data){
            if(!life.alive||ticket!==client.serial||id!==client.requestId)return;
            client.controlRequest=null;
            if(ok)client.applySnapshot(data);else client.announce("搜索请求失败："+String(data.error||"服务未就绪"));
            client.refresh();
        });
    }
    function stop(teardown) {
        cancelPoll();var id=requestId;requestId="";
        if(!id)return;
        var ticket=serial,life=lifetime;
        // Do not abort the stop request on page teardown; server also has a deadline.
        var done=teardown?function(){}:function(ok,data){if(life.alive&&ticket===client.serial&&!client.requestId&&ok)client.applySnapshot(data);};
        controlRequest=Api.request("/api/action","bt_stop:"+owner+":"+id,done);
    }
    Timer { interval:500;repeat:true;running:client.alive;onTriggered:client.refresh() }
    Timer { id:watchdog;interval:3000;onTriggered:{client.cancelPoll();client.announce("蓝牙状态读取超时");} }
    Component.onCompleted:refresh()
    Component.onDestruction:{lifetime.alive=false;alive=false;stop(true);}
}
