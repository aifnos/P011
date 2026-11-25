import QtQuick 2.10
import "Theme.js" as Theme
Rectangle {
    id: root
    objectName: "extensionPage"
    color: Theme.background
    property string endpoint: typeof nextEndpoint !== "undefined" ? nextEndpoint : ""
    property string token: typeof nextToken !== "undefined" ? nextToken : ""
    property bool bootstrapAllowed: false
    property bool connected: token !== ""
    property string pageName: ""
    property string initialPage: ""
    property string pendingReceivedDirectory: ""
    property bool immersiveFeature:pageName==="Mta"
    property string mtaServiceUrl:typeof mtaEndpoint!=="undefined"?mtaEndpoint:""
    property string mtaAccessToken:typeof mtaToken!=="undefined"?mtaToken:""
    property bool mtaBootstrapAllowed:false
    property bool mtaAvailable:/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(mtaServiceUrl)&&(mtaAccessToken!==""||mtaBootstrapAllowed)
    property bool hostPreview:false
    property url mtaHostSource:Qt.resolvedUrl("../mta/MtaHost.qml")
    property string message: ""
    property var telemetry: ({metrics:{},history:[],scores:{},transfer:{},addresses:[]})
    property var lifetime: ({alive:true,epoch:0})
    property var pending: []
    signal exitRequested()
    signal compositionReady()
    readonly property bool compositionLoaded:pageName==="Mta"&&child.status===Loader.Ready&&child.item&&child.item.contentLoaded===true
    function request(path,form,done) {
        if(!/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.test(endpoint)||!token){if(done)done(false,{error:"本地文件服务未就绪"});return;}
        var xhr=new XMLHttpRequest(), guard=lifetime, epoch=guard.epoch, finished=false;
        function finish(ok,result) {
            if(finished)return; finished=true;
            if(guard.alive && guard.epoch===epoch && done)done(ok,result);
        }
        xhr.onreadystatechange=function() {
            if(xhr.readyState!==XMLHttpRequest.DONE)return;
            try {var o=JSON.parse(xhr.responseText);finish(xhr.status===200&&o.ok,o.ok?o.data:{error:o.error});}
            catch(e){finish(false,{error:"本地服务未就绪"});}
        };
        try {
            xhr.open(form===null?"GET":"POST",endpoint+path);
            if(path==="/api/native/bootstrap")xhr.setRequestHeader("X-P011-Native-UI","qml-runtime");
            else xhr.setRequestHeader("X-P011-Token",token);
            var body="";
            if(form!==null) {
                var fields=[];for(var k in form)fields.push(encodeURIComponent(k)+"="+encodeURIComponent(form[k]));
                body=fields.join("&");xhr.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
            }
            pending.push({xhr:xhr,at:Date.now(),finished:function(){return finished;},expire:function(){xhr.abort();finish(false,{error:"请求超时"});}});
            xhr.send(body);
        }catch(e){finish(false,{error:"本地服务连接失败"});}
    }
    function connectBackend() {
        if(token){connected=true;refresh();return;}
        if(!bootstrapAllowed){toast("等待本地服务");return;}
        request("/api/native/bootstrap",null,function(ok,d){
            if(!ok){toast(d.error);return;}
            token=d.token;connected=true;refresh();
        });
    }
    function refresh() {if(connected)request("/api/state",null,function(ok,d){if(ok)telemetry=d;else toast(d.error);});}
    function toast(text) {message=text;toastTimer.restart();}
    function open(name) {
        if(["","Files","Mta"].indexOf(name)<0){toast("此互传会话仅提供文件中心");return;}
        if(name && !connected){toast("本地服务正在初始化");return;}
        if(child.item&&child.item.prepareLeave&&child.item.prepareLeave(name)===false)return;
        message="";
        lifetime.epoch++;pageName=name;
        child.setSource(name?Qt.resolvedUrl(name==="Mta"?"MtaEmbedded.qml":name+"Page.qml"):"",name?{app:root}:{});
        if(connected)request("/api/ui/event",{event:"page_"+(name||"Home")},null);
        refresh();
    }
    function openReceivedDirectory() {
        pendingReceivedDirectory="Received";
        open("Files");
        applyReceivedTarget();
    }
    function applyReceivedTarget() {
        if(pageName!=="Files"||!child.item||child.item.objectName!=="filesPage")return;
        if(pendingReceivedDirectory!==""){var directory=pendingReceivedDirectory;pendingReceivedDirectory="";child.item.directory=directory;child.item.offset=0;child.item.load();}
    }
    function back() {
        if(child.item&&child.item.handleBack&&child.item.handleBack())return;
        if(pageName)open("");else requestExit();
    }
    function requestExit() {
        if(child.item&&child.item.prepareLeave&&child.item.prepareLeave("Exit")===false)return;
        exitRequested();
    }
    Item {
        width:parent.width;height:64;visible:!root.immersiveFeature
        Item {
            objectName:"backButton";x:0;y:0;width:76;height:64
            Canvas {
                x:21;y:15;width:32;height:34
                onPaint:{var c=getContext("2d");c.strokeStyle="#ffffff";c.lineWidth=4;c.lineCap="round";c.lineJoin="round";c.beginPath();c.moveTo(21,4);c.lineTo(8,17);c.lineTo(21,30);c.stroke();}
            }
            MouseArea {anchors.fill:parent;onClicked:root.back()}
        }
        Label {
            objectName:"toolboxHeaderTitle"
            x:root.pageName?202:136;y:4;width:root.pageName?346:528;height:56
            // Loader disposal may retain the previous item for one event turn.
            // Home is defined by navigation state, never by that stale item.
            text:(root.pageName===""?"接收与文件":child.item&&child.item.headerTitle?child.item.headerTitle:"文件中心")+(root.hostPreview?" · HOST":"")
            font.pixelSize:root.pageName?28:36;horizontalAlignment:Text.AlignHCenter
            elide:Text.ElideMiddle
        }
        Button {
            objectName:"headerAction";x:root.pageName?560:672;y:7;width:root.pageName?106:116;height:50
            visible:!root.pageName || !!(child.item&&child.item.headerAction)
            text:!root.pageName?"退出":child.item&&child.item.headerAction?String(child.item.headerAction):""
            enabled:!child.item || child.item.actionEnabled===undefined || child.item.actionEnabled
            fontSize:24
            onClicked:{if(!root.pageName)root.requestExit();else if(child.item&&child.item.primaryAction)child.item.primaryAction();}
        }
    }
    Button {
        objectName:"fileCenterReturnMta";x:80;y:7;width:110;height:50;fontSize:23;text:"互传"
        visible:root.pageName==="Files";enabled:root.mtaAvailable;onClicked:root.open("Mta")
    }
    Button {
        objectName:"fileCenterExit";x:676;y:7;width:116;height:50;fontSize:23;text:"退出"
        visible:root.pageName==="Files";onClicked:root.requestExit()
    }
    Flickable {
        id:homeScroller;objectName:"toolboxHomeScroller";x:16;y:78;width:parent.width-32;height:184
        visible:!root.pageName;clip:true;contentWidth:homeRow.width;contentHeight:height
        boundsBehavior:Flickable.StopAtBounds;flickableDirection:Flickable.HorizontalFlick
        Row {id:homeRow;spacing:12
        Repeater {
            model:[{name:"文件中心",kind:"folder",page:"Files",hint:"收件 / 图片 / 文本 / 影音"},
                   {name:"手机互传",kind:"transfer",page:"Mta",hint:"原厂互传 / 手动开始接收"}]
            delegate:Item {
                objectName:"home"+modelData.page
                width:183;height:182
                NativeIcon {anchors.horizontalCenter:parent.horizontalCenter;y:0;width:96;height:96;kind:modelData.kind;opacity:homeArea.pressed?.5:1}
                Label {x:0;y:110;width:parent.width;height:38;text:modelData.name;font.pixelSize:28;horizontalAlignment:Text.AlignHCenter}
                Label {x:0;y:148;width:parent.width;height:26;text:modelData.hint;font.pixelSize:18;color:Theme.secondary;horizontalAlignment:Text.AlignHCenter}
                MouseArea {id:homeArea;anchors.fill:parent;onClicked:{if(modelData.page==="Mta"&&!root.mtaAvailable){root.toast("互传服务未就绪，请从当前接入会话打开");return;}root.open(modelData.page)}}
            }
        }
        }
    }
    Rectangle {
        x:360;y:264;width:80;height:3;radius:2;color:Theme.button
        visible:!root.pageName&&homeRow.width>768
        Rectangle {width:38;height:3;radius:2;color:Theme.secondary;x:42*Math.min(1,Math.max(0,homeScroller.contentX/Math.max(1,homeRow.width-homeScroller.width)))}
    }
    Loader {
        id:child;objectName:"featureLoader";x:0;y:root.immersiveFeature?0:64;width:parent.width;height:parent.height-y
        visible:root.pageName!==""
        onLoaded:root.applyReceivedTarget()
        onStatusChanged:if(status===Loader.Error)root.toast("页面加载失败")
    }
    Connections {target:child.item;ignoreUnknownSignals:true;onContentReady:root.compositionReady()}
    Rectangle {
        x:14;y:parent.height-54;width:parent.width-28;height:48;radius:6;z:50
        visible:root.message!=="";color:"#ef3c3d42"
        Label {anchors.fill:parent;anchors.margins:8;text:root.message;font.pixelSize:24;elide:Text.ElideRight}
        MouseArea {anchors.fill:parent;onClicked:root.message=""}
    }
    Timer {id:toastTimer;interval:4000;onTriggered:root.message=""}
    Timer {objectName:"telemetryTimer";interval:2000;repeat:true;running:root.visible&&root.connected;onTriggered:root.refresh()}
    Timer {
        interval:500;repeat:true;running:true
        onTriggered:{var keep=[];for(var i=0;i<root.pending.length;i++){var p=root.pending[i];if(p.finished())continue;if(Date.now()-p.at>6000)p.expire();else keep.push(p);}root.pending=keep;}
    }
    Keys.onEscapePressed:back()
    Component.onCompleted:{connectBackend();if(initialPage==="Mta")open("Mta");}
    Component.onDestruction:{lifetime.alive=false;for(var i=0;i<pending.length;i++)pending[i].xhr.abort();}
}
