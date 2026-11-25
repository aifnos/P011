import QtQuick 2.10

// Parent-owned 800x268; no extra offset/rotation. Leaving the actual MTA
// surface first asks its original cancel endpoint, then observes quiescence.
Item {
    id:wrapper;objectName:"mtaEmbedded"
    property var app
    property string headerTitle:"手机互传"
    property var lastStatus:({})
    property bool knownStatus:false
    property bool statusPending:false
    property bool exitPending:false
    property bool exitApproved:false
    property bool cancelIssued:false
    property bool cancelConfirmed:false
    property bool cancelFailed:false
    property int exitGeneration:0
    property string exitTarget:""
    property var lifetime:({alive:true,epoch:0})
    property var pending:[]
    readonly property var host:hostLoader.item
    property bool contentLoaded:false
    signal contentReady()
    readonly property string connectionKey:(app?app.mtaServiceUrl:"")+"|"+(host?host.accessToken:"")
    function request(path,body,done){
        if(!app||!host||!/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(app.mtaServiceUrl)||!host.accessToken){done(false,{});return;}
        var xhr=new XMLHttpRequest(),guard=lifetime,epoch=guard.epoch,finished=false;
        function finish(ok,value){if(finished)return;finished=true;if(guard.alive&&guard.epoch===epoch)done(ok,value);}
        xhr.onreadystatechange=function(){if(xhr.readyState!==XMLHttpRequest.DONE)return;
            try{var value=JSON.parse(xhr.responseText);finish(xhr.status===200&&value.ok!==false,value);}catch(e){finish(false,{});}};
        try{xhr.open(body===null?"GET":"POST",app.mtaServiceUrl+path);
            xhr.setRequestHeader("X-P011-MTA-Token",host.accessToken);
            if(body!==null)xhr.setRequestHeader("Content-Type","application/json");
            pending.push({xhr:xhr,at:Date.now(),finished:function(){return finished;},expire:function(){xhr.abort();finish(false,{});}});
            xhr.send(body===null?"":JSON.stringify(body));
        }catch(e){finish(false,{});}
    }
    function invalidate(){
        lifetime.epoch++;exitGeneration++;knownStatus=false;statusPending=false;exitApproved=false;
        for(var i=0;i<pending.length;i++)pending[i].xhr.abort();pending=[];
    }
    function quiescent(value){
        var state=String(value.state||""),network=value.networkRecovery||{};
        return ["idle","completed","complete","failed","error"].indexOf(state)>=0&&
            value.discoverable===false&&value.scanning===false&&value.restorePending===false&&
            !value.request&&network.restorePending!==true&&network.recoveryLocked!==true;
    }
    function refresh(){
        if(statusPending||(exitPending&&!cancelConfirmed))return;statusPending=true;
        var generation=exitGeneration,exitRead=exitPending&&cancelConfirmed;
        request("/v1/status",null,function(ok,value){
            statusPending=false;var current=value.status||value.data||value;
            if(!ok||!current||typeof current.state!=="string"){knownStatus=false;return;}
            knownStatus=true;lastStatus=current;
            if(exitRead&&exitPending&&cancelConfirmed&&generation===exitGeneration&&quiescent(current)){
                exitApproved=true;exitPending=false;
                if(exitTarget==="Received")app.openReceivedDirectory();
                else if(exitTarget==="Exit")app.requestExit();
                else app.open(exitTarget);
            }
        });
    }
    function cancelAndWait(){
        if(cancelIssued)return;cancelIssued=true;
        var generation=exitGeneration;
        request("/v1/action",{action:"cancel"},function(ok,value){
            if(generation!==exitGeneration||!exitPending)return;
            if(!ok){cancelFailed=true;app.toast("停止尚未确认，请保留此页并重试；会话停止由后台核验");return;}
            cancelConfirmed=true;refresh();
        });
    }
    function requestExit(target){
        if(exitPending&&!cancelFailed)return;
        invalidate();cancelIssued=false;cancelConfirmed=false;cancelFailed=false;
        exitTarget=typeof target==="string"?target:"";
        if(["","Files","Received","Exit"].indexOf(exitTarget)<0)exitTarget="";
        exitPending=true;
        if(host&&host.suspendForLeave)host.suspendForLeave();
        app.toast("正在结束接收并核对网络，完成后再切换页面");
        cancelAndWait();
    }
    function prepareLeave(target){
        if(exitApproved){if(host)host.resetHost();return true;}
        requestExit(target);return false;
    }
    function handleBack(){
        if(host&&host.stage==="keyboard"&&!exitPending){host.stage="mta";return true;}
        requestExit("");return true;
    }
    onConnectionKeyChanged:{invalidate();cancelIssued=false;cancelConfirmed=false;cancelFailed=false;exitPending=false;lastStatus={};refresh();}
    Loader {
        id:hostLoader;objectName:"embeddedMtaHostLoader";anchors.fill:parent;enabled:!wrapper.exitPending
        Component.onCompleted:if(app)hostLoader.setSource(app.mtaHostSource,{endpoint:app.mtaServiceUrl,
            accessToken:app.mtaAccessToken,bootstrapAllowed:false,hostPreview:app.hostPreview})
        onLoaded:{item.exitRequested.connect(wrapper.requestExit);
            item.receivedDirectoryRequested.connect(function(){wrapper.requestExit("Received");});
            wrapper.contentLoaded=true;wrapper.contentReady();}
    }
    Binding {target:wrapper.host;property:"endpoint";value:app?app.mtaServiceUrl:"";when:wrapper.host!==null}
    Binding {target:wrapper.host;property:"accessToken";value:app?app.mtaAccessToken:"";when:wrapper.host!==null&&app&&app.mtaAccessToken!==""}
    Rectangle {
        anchors.fill:parent;color:"#e5101115";visible:wrapper.exitPending;z:60
        Text {x:24;y:58;width:752;height:92;color:"#a7a9b7";font.pixelSize:24;text:wrapper.cancelFailed?
            "停止请求尚未确认；不会直接打开文件或把网络恢复当作成功":"正在结束接收并核对网络…";
            horizontalAlignment:Text.AlignHCenter;verticalAlignment:Text.AlignVCenter;wrapMode:Text.Wrap}
        MouseArea {anchors.fill:parent}
        Button {x:288;y:174;width:224;height:62;text:"重试停止";fontSize:24;visible:wrapper.cancelFailed;
            onClicked:wrapper.requestExit(wrapper.exitTarget)}
    }
    Timer {interval:500;repeat:true;running:wrapper.visible;onTriggered:wrapper.refresh()}
    Timer {interval:250;repeat:true;running:true;onTriggered:{
        var keep=[];for(var i=0;i<wrapper.pending.length;i++){var row=wrapper.pending[i];if(row.finished())continue;
            if(Date.now()-row.at>8000)row.expire();else keep.push(row);}wrapper.pending=keep;
    }}
    Component.onCompleted:refresh()
    Component.onDestruction:{lifetime.alive=false;for(var i=0;i<pending.length;i++)pending[i].xhr.abort();}
}
