import QtQuick 2.10
import "MtaTheme.js" as Theme

Rectangle {
    id: host
    width:800; height:268; color:Theme.background
    property string endpoint:""
    property string accessToken:""
    property bool bootstrapAllowed:false
    property bool hostPreview:false
    property string stage:"mta"
    property var fileRows:[]
    property var picked:[]
    property string fileMode:"select"
    property string message:""
    property bool initialized:false
    property var lifetime:({alive:true,epoch:0})
    property var pending:[]
    signal exitRequested()

    function resetHost() {
        lifetime.epoch++;
        for(var i=0;i<pending.length;i++)pending[i].xhr.abort();
        pending=[];fileRows=[];picked=[];message="";
        if(page)page.selectedFiles=[];
    }
    function request(path,isBootstrap,done) {
        if(!/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(endpoint) || (!isBootstrap&&!accessToken)) {done(false,{});return;}
        var xhr=new XMLHttpRequest(),guard=lifetime,epoch=guard.epoch,finished=false;
        function finish(ok,value) {if(finished)return;finished=true;
            if(guard.alive&&guard.epoch===epoch)done(ok,value);}
        xhr.onreadystatechange=function(){if(xhr.readyState!==XMLHttpRequest.DONE)return;
            try {finish(xhr.status===200,JSON.parse(xhr.responseText));}catch(e){finish(false,{});}};
        try {xhr.open("GET",endpoint+path);
            if(!isBootstrap)xhr.setRequestHeader("X-P011-MTA-Token",accessToken);
            pending.push({xhr:xhr,at:Date.now(),finished:function(){return finished;},expire:function(){xhr.abort();finish(false,{});}});
            xhr.send();
        }catch(e){finish(false,{});}
    }

    function fetchFiles(mode) {
        fileMode=mode;fileRows=[];message="正在读取文件目录";stage="files";
        request("/v1/files",false,function(ok,value){
            if(!ok){fileRows=[];message="文件目录暂不可用";return;}
            try {var rows=value.files || [];
                fileRows=mode==="received"?rows.filter(function(row){return row.name.indexOf("Received/")===0;}):rows;
                message="";
                var keep=[];for(var i=0;i<picked.length;i++)for(var j=0;j<rows.length;j++)if(picked[i].id===rows[j].id)keep.push(rows[j]);picked=keep;
            } catch(e){message="文件目录返回异常";}
        });
    }
    function contains(id) {for(var i=0;i<picked.length;i++)if(picked[i].id===id)return true;return false;}
    function choose(row) {var next=[];for(var i=0;i<picked.length;i++)if(picked[i].id!==row.id)next.push(picked[i]);
        if(!contains(row.id))next.push(row);picked=next;}
    function bootstrap() {
        if(!initialized || !bootstrapAllowed || !endpoint || accessToken)return;
        request("/v1/bootstrap",true,function(ok,value){
            if(ok&&value.token)accessToken=value.token;else message="本地服务未就绪";
        });
    }
    onEndpointChanged:{resetHost();if(initialized&&bootstrapAllowed){accessToken="";bootstrap();}}
    onAccessTokenChanged:resetHost()
    Component.onCompleted:{initialized=true;bootstrap();}
    Component.onDestruction:{lifetime.alive=false;resetHost();}
    Timer {interval:250;running:host.lifetime.alive;repeat:true;onTriggered:{
        var keep=[];for(var i=0;i<host.pending.length;i++){var row=host.pending[i];if(row.finished())continue;
            if(Date.now()-row.at>8000)row.expire();else keep.push(row);}host.pending=keep;
    }}

    MtaPage {
        id:page;anchors.fill:parent;visible:host.stage==="mta"
        serviceUrl:host.endpoint;token:host.accessToken;nicknameEditorAvailable:true;hostPreview:host.hostPreview
        onExitRequested:host.exitRequested()
        onFileCenterRequested:host.fetchFiles(mode)
        onNicknameEditRequested:{host.stage="keyboard";board.open(currentName,false);}
    }
    Rectangle {
        anchors.fill:parent;visible:host.stage==="files";color:Theme.background
        MtaButton {x:8;y:4;width:112;height:42;text:"‹ 互传";fontSize:22;onClicked:host.stage="mta"}
        MtaLabel {x:132;y:4;width:470;height:42;font.pixelSize:25;text:host.fileMode==="received"?"接收目录 · 只读":"选择要发送的文件"}
        MtaButton {x:648;y:4;width:144;height:42;text:"完成 · "+host.picked.length;fontSize:22;accent:true;visible:host.fileMode==="select";
            onClicked:{page.selectedFiles=host.picked;host.stage="mta";}}
        ListView {
            objectName:"mtaFilePicker";x:8;y:host.fileMode==="received"?79:54;width:784;height:host.fileMode==="received"?183:208;spacing:6;clip:true
            model:host.fileRows
            delegate:Rectangle {
                width:784;height:62;radius:8;color:host.fileMode==="select"&&host.contains(modelData.id)?Theme.accent:Theme.row
                MtaLabel {x:12;y:2;width:620;height:38;text:modelData.name;font.pixelSize:22;elide:Text.ElideMiddle}
                MtaLabel {x:12;y:38;width:650;height:22;text:page.formatBytes(modelData.size);font.pixelSize:17;color:Theme.secondary}
                MtaLabel {x:668;width:108;height:62;text:host.fileMode==="select"?(host.contains(modelData.id)?"已选择":"选择"):"已保存";font.pixelSize:22;horizontalAlignment:Text.AlignHCenter}
                MouseArea {anchors.fill:parent;enabled:host.fileMode==="select";onClicked:host.choose(modelData)}
            }
        }
        MtaLabel {x:132;y:46;width:650;height:29;visible:host.fileMode==="received";text:"目录只读 · 文件打开功能尚未接入";font.pixelSize:17;color:Theme.secondary}
        MtaLabel {anchors.centerIn:parent;width:600;height:90;horizontalAlignment:Text.AlignHCenter;wrapMode:Text.Wrap;
            visible:host.fileRows.length===0;text:host.message || "目录中没有可用文件";font.pixelSize:24}
    }
    Item {
        anchors.fill:parent;visible:host.stage==="keyboard"
        // The reused board owns its internal visible flag. Its open()/finish()
        // must not break the host's stage binding or overlay the next page.
        MtaKeyboard {
        id:board;objectName:"mtaKeyboard";anchors.fill:parent
        onAccepted:{page.applyNickname(value);host.stage="mta";}
        onCanceled:host.stage="mta"
        // Reuse the project keyboard, not an unproven original-private ABI.
        // Pinyin dictionary is not loaded by this standalone candidate yet.
        onNativeRequested:{chinese=false;page.toast("当前名称输入仅支持英文；可返回继续互传");}
        }
    }
}
