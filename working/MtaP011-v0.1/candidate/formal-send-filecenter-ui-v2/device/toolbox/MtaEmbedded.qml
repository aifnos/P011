import QtQuick 2.10

// A single 800x268 content page. The toolbox suppresses its outer header here.
Item {
    id: wrapper
    objectName: "mtaEmbedded"
    property var app
    property string headerTitle: "手机互传"
    property var lastStatus: ({})
    property bool knownStatus: false
    property bool statusPending: false
    property bool exitPending: false
    property bool exitApproved: false
    property bool cancelIssued: false
    property bool cancelConfirmed: false
    property bool cancelFailed: false
    property int exitGeneration:0
    property string exitTarget:""
    property string receivedOpenPath:""
    property var lifetime: ({alive:true,epoch:0})
    property var pending: []
    readonly property var host:hostLoader.item
    signal contentReady()
    property bool contentLoaded:false
    readonly property string connectionKey:(app?app.mtaServiceUrl:"")+"|"+(host?host.accessToken:"")
    readonly property bool networkBusy: lastStatus.discoverable===true||lastStatus.scanning===true||lastStatus.restorePending===true||!!lastStatus.request||lastStatus.state==="connecting"||lastStatus.state==="transferring"||lastStatus.state==="restoring"

    function request(path, body, done) {
        if(!app || !host || !/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(app.mtaServiceUrl) || !host.accessToken){done(false,{});return;}
        var xhr=new XMLHttpRequest(),guard=lifetime,epoch=guard.epoch,finished=false;
        function finish(ok,value){if(finished)return;finished=true;if(guard.alive&&guard.epoch===epoch)done(ok,value);}
        xhr.onreadystatechange=function(){if(xhr.readyState!==XMLHttpRequest.DONE)return;
            try{finish(xhr.status===200,JSON.parse(xhr.responseText));}catch(e){finish(false,{});}};
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
        return ["idle","completed","complete","failed","error"].indexOf(state)>=0 && value.discoverable===false && value.scanning===false && value.restorePending===false && !value.request && network.restorePending!==true && network.recoveryLocked!==true;
    }
    function refresh(){
        if(statusPending || (exitPending&&!cancelConfirmed))return;statusPending=true;
        var generation=exitGeneration,exitRead=exitPending&&cancelConfirmed;
        request("/v1/status",null,function(ok,value){statusPending=false;
            if(ok){knownStatus=true;lastStatus=value.status||value.data||value;
                if(exitRead&&exitPending&&cancelConfirmed&&generation===exitGeneration&&quiescent(lastStatus)){
                    exitApproved=true;exitPending=false;
                    if(exitTarget==="Received"){var path=receivedOpenPath;receivedOpenPath="";app.openReceivedDirectory();if(path!=="")app.openReceivedFile(path);}else app.open(exitTarget);
                }}
            else knownStatus=false;
        });
    }
    function cancelAndWait(){
        if(cancelIssued)return;cancelIssued=true;
        var generation=exitGeneration;
        request("/v1/action",{action:"cancel"},function(ok,value){
            if(generation!==exitGeneration||!exitPending)return;
            if(!ok){cancelFailed=true;app.toast("停止请求尚未确认，请保留此页；返回可重试，或使用会话停止");return;}
            cancelConfirmed=true;refresh();
        });
    }
    function requestExit(target){
        if(exitPending&&!cancelFailed)return;
        invalidate();cancelIssued=false;cancelConfirmed=false;cancelFailed=false;
        exitTarget=typeof target==="string"?target:"";
        if(["","Files","Received","Games","Dashboard","Bili"].indexOf(exitTarget)<0)exitTarget="";
        exitPending=true;app.toast("正在停止互传，恢复完成后返回工具箱");
        cancelAndWait();
    }
    function prepareLeave(target){
        if(exitApproved){if(host)host.resetHost();return true;}
        requestExit(target);return false;
    }
    function handleBack(){
        if(host&&host.stage!=="mta"){host.stage="mta";return true;}
        requestExit("");return true;
    }
    onConnectionKeyChanged:{invalidate();cancelIssued=false;cancelConfirmed=false;cancelFailed=false;exitPending=false;lastStatus={};refresh();}

    Loader {
        id:hostLoader;objectName:"embeddedMtaHostLoader";anchors.fill:parent
        Component.onCompleted:if(app)hostLoader.setSource(app.mtaHostSource,{endpoint:app.mtaServiceUrl,accessToken:app.mtaAccessToken,bootstrapAllowed:app.mtaBootstrapAllowed,hostPreview:app.hostPreview})
        onLoaded:{item.exitRequested.connect(wrapper.requestExit);item.receivedFileRequested.connect(function(path){wrapper.receivedOpenPath=path;wrapper.requestExit("Received");});wrapper.contentLoaded=true;wrapper.contentReady();}
    }
    Binding {target:wrapper.host;property:"endpoint";value:app?app.mtaServiceUrl:"";when:wrapper.host!==null}
    Binding {target:wrapper.host;property:"accessToken";value:app?app.mtaAccessToken:"";when:wrapper.host!==null&&app&&app.mtaAccessToken!==""}
    Button {
        objectName:"receivedOpenFileCenter";x:648;y:4;width:144;height:42;fontSize:21;text:"文件中心"
        visible:wrapper.host&&wrapper.host.stage==="files"&&wrapper.host.fileMode==="received"
        enabled:wrapper.knownStatus&&!wrapper.networkBusy&&!wrapper.exitPending
        onClicked:wrapper.requestExit("Received")
    }
    Timer {interval:500;repeat:true;running:wrapper.visible;onTriggered:wrapper.refresh()}
    Timer {interval:250;repeat:true;running:true;onTriggered:{
        var keep=[];for(var i=0;i<wrapper.pending.length;i++){var row=wrapper.pending[i];if(row.finished())continue;if(Date.now()-row.at>8000)row.expire();else keep.push(row);}wrapper.pending=keep;
    }}
    Component.onCompleted:refresh()
    Component.onDestruction:{lifetime.alive=false;for(var i=0;i<pending.length;i++)pending[i].xhr.abort();}
}

