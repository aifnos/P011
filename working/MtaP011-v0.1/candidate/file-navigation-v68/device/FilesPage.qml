import QtQuick 2.10
import "Theme.js" as Theme
Item {
    id:page;objectName:"filesPage"
    property var app
    property string directory:""
    property int offset:0
    property int nextOffset:-1
    property var entries:[]
    property var selected:({})
    property bool transferView:false
    property bool loading:false
    property bool leaving:false
    property int listingGeneration:0
    property int openGeneration:0
    property string pendingOpenPath:""
    property int addressIndex:0
    property var transfer:app?app.telemetry.transfer:({})
    property var addresses:app?app.telemetry.addresses:[]
    property var audioState:({})
    property double audioGeneration:-1
    property bool backendAudio:false
    property bool audioPollPending:false
    property double sampleAt:0
    property int tick:0
    property double commandSerial:Date.now()*1000
    property real volume:.25
    property string headerTitle:transferView?"无线传文件":selected.path?selected.path.split("/").pop():directory?folderName(directory.split("/").pop()):"文件中心"
    property string headerAction:selected.kind?"文件":"传文件"
    property bool actionEnabled:!loading
    function folderName(name){return ({Music:"音乐 / 视频",Pictures:"图片",Text:"文本",GameResources:"游戏资源",Screenshots:"截图",Exports:"导出记录",Received:"已收到"})[name]||name;}
    function kindName(name){return ({audio:"音频",video:"视频",image:"图片",text:"文本",resource:"资源"})[name]||"文件";}
    function formatBytes(value){var n=Math.max(0,Number(value)||0);return n<1024?Math.floor(n)+" B":n<1048576?(n/1024).toFixed(1)+" KiB":n<1073741824?(n/1048576).toFixed(1)+" MiB":(n/1073741824).toFixed(1)+" GiB";}
    function directoryTitle(){var bits=directory.split("/");if(bits.length)bits[0]=folderName(bits[0]);return bits.join("/");}
    function invalidateOpen(){openGeneration++;if(pendingOpenPath!==""){pendingOpenPath="";loading=false;}}
    function load(){if(leaving)return;invalidateOpen();var generation=++listingGeneration;loading=true;app.request("/api/files?path="+encodeURIComponent(directory)+"&offset="+offset,null,function(ok,d){if(leaving||generation!==listingGeneration)return;loading=false;if(ok){entries=d.entries;nextOffset=d.next===null?-1:d.next;if(d.limited)app.toast("目录较大，请按文件夹分类");}else app.toast(d.error);});}
    function stop(){invalidateOpen();commandSerial++;if(backendAudio)app.request("/api/audio/stop",{command:commandSerial},null);backendAudio=false;audioGeneration=-1;audioState={};if(videoLoader.item)videoLoader.item.stop();videoLoader.source="";}
    function primaryAction(){invalidateOpen();if(selected.kind){stop();selected={};return;}transferView=!transferView;if(transferView)stop();}
    function handleBack(){invalidateOpen();if(selected.kind){stop();selected={};return true;}if(transferView){transferView=false;return true;}if(directory){directory=directory.split("/").slice(0,-1).join("/");offset=0;load();return true;}return false;}
    function openFile(item){
        if(leaving||loading)return;
        if(item.kind==="directory"){directory=item.path;offset=0;selected={};load();return;}
        stop();var generation=++openGeneration,path=item.path,requestDirectory=directory;pendingOpenPath=path;loading=true;
        app.request("/api/open?path="+encodeURIComponent(path),null,function(ok,d){
            if(leaving||generation!==openGeneration||pendingOpenPath!==path||directory!==requestDirectory)return;
            pendingOpenPath="";loading=false;if(!ok){app.toast(d.error);return;}selected=d;
            if(d.kind==="audio")playAudio();
            else if(d.kind==="video")videoLoader.setSource(Qt.resolvedUrl("VideoPane.qml"),{mediaUrl:d.url,volume:page.volume,app:app});
        });
    }
    function playAudio(){
        backendAudio=true;audioState={status:"starting",position_ms:0,duration_ms:0,process_alive:true};
        audioGeneration=-1;commandSerial++;loading=true;
        app.request("/api/audio/play",{path:selected.path,volume:Math.round(volume*100),command:commandSerial},function(ok,d){
            loading=false;if(ok){audioGeneration=d.generation;audioState=d;sampleAt=Date.now();}
            else{backendAudio=false;audioState={};app.toast(d.error);}
        });
    }
    function prepareLeave(){leaving=true;stop();}
    function stamp(ms){var s=Math.floor(Number(ms||0)/1000);return Math.floor(s/60)+":"+(s%60<10?"0":"")+s%60;}
    function position(){var t=tick;if(selected.kind!=="audio")return videoLoader.item?videoLoader.item.position:0;var p=Number(audioState.position_ms||0);if(audioState.status==="playing")p+=Math.max(0,Math.min(250,Date.now()-sampleAt));return Math.min(Number(audioState.duration_ms||p),p);}
    function duration(){return selected.kind==="audio"?Number(audioState.duration_ms||0):(videoLoader.item?videoLoader.item.duration:0);}
    onDirectoryChanged:invalidateOpen()
    onVolumeChanged:if(videoLoader.item)videoLoader.item.volume=volume
    Grid {
        x:12;y:9;columns:4;spacing:10
        visible:!page.directory&&!page.selected.kind&&!page.transferView
        Repeater {
            model:["Music","Pictures","Text","GameResources","Screenshots","Exports","Received","Mta"]
            delegate:Button {objectName:"fileFolder"+modelData;width:185;height:80;text:modelData==="Mta"?"手机互传":page.folderName(modelData);fontSize:26;accent:modelData==="Mta";
                onClicked:{if(modelData==="Mta"){if(app.mtaAvailable)app.open("Mta");else app.toast("互传服务未就绪");}else page.openFile({kind:"directory",path:modelData});}}
        }
    }
    Item {
        anchors.fill:parent;visible:page.directory!==""&&!page.selected.kind&&!page.transferView
        Label {x:14;y:0;width:480;height:46;font.pixelSize:24;color:Theme.secondary;text:page.directoryTitle();elide:Text.ElideMiddle}
        Button {x:526;y:0;width:112;height:46;text:"刷新";fontSize:24;enabled:!page.loading;onClicked:page.load()}
        Button {x:650;y:0;width:138;height:46;text:"下一页";fontSize:24;enabled:page.nextOffset>=0&&!page.loading;onClicked:{page.offset=page.nextOffset;page.load();}}
        ListView {
            objectName:"fileList";x:12;y:53;width:parent.width-24;height:parent.height-56;clip:true;spacing:4;model:page.entries
            delegate:Rectangle {
                objectName:"fileEntry"+index
                width:776;height:64;radius:6;color:fileArea.pressed?"#74757e":Theme.row
                Label {x:16;y:3;width:584;height:36;text:(modelData.kind==="directory"?"> ":"")+modelData.name;font.pixelSize:28;elide:Text.ElideMiddle}
                Label {objectName:"fileEntrySize"+index;x:16;y:38;width:620;height:23;text:modelData.kind==="directory"?"文件夹":page.kindName(modelData.kind)+" · "+page.formatBytes(modelData.bytes);font.pixelSize:18;color:Theme.secondary}
                Label {x:715;y:0;width:48;height:64;text:">";font.pixelSize:32;horizontalAlignment:Text.AlignHCenter;color:Theme.secondary}
                MouseArea {id:fileArea;anchors.fill:parent;enabled:!page.loading;onClicked:page.openFile(modelData)}
            }
            Label {anchors.centerIn:parent;visible:page.entries.length===0;text:page.loading?"正在读取…":"暂无文件";color:Theme.secondary}
        }
    }
    Image {
        objectName:"imagePreview";x:12;y:3;width:parent.width-24;height:parent.height-8
        visible:page.selected.kind==="image"&&!page.transferView;source:visible?page.selected.url:""
        sourceSize.width:1200;sourceSize.height:600;asynchronous:true;fillMode:Image.PreserveAspectFit
        onStatusChanged:if(status===Image.Error)app.toast("图片无法解码")
    }
    Flickable {
        x:18;y:2;width:parent.width-36;height:parent.height-7;clip:true
        visible:page.selected.kind==="text"&&!page.transferView;contentHeight:bodyText.height
        Label {id:bodyText;objectName:"textPreview";width:parent.width;text:(page.selected.text||"")+(page.selected.truncated?"\n——仅预览前 64 KiB——":"");textFormat:Text.PlainText;wrapMode:Text.WrapAnywhere;font.pixelSize:28}
    }
    Item {
        anchors.fill:parent;visible:!page.transferView&&(page.selected.kind==="audio"||page.selected.kind==="video")
        Loader {id:videoLoader;x:0;y:0;width:parent.width;height:122;visible:page.selected.kind==="video";onStatusChanged:if(status===Loader.Error)app.toast("当前视频插件不可用")}
        Label {x:30;y:4;width:740;height:38;visible:page.selected.kind==="audio";text:page.audioState.status==="starting"?"准备中…":"本地音乐";font.pixelSize:28;color:Theme.accent;horizontalAlignment:Text.AlignHCenter}
        Label {x:30;y:42;width:740;height:36;visible:page.selected.kind==="audio";text:page.stamp(page.position())+" / "+page.stamp(page.duration());font.pixelSize:28;horizontalAlignment:Text.AlignHCenter}
        Row {
            x:195;y:page.selected.kind==="audio"?90:130;spacing:14
            Button {width:96;height:56;text:"音−";onClicked:page.volume=Math.max(0,page.volume-.1)}
            Button {objectName:"mediaPlayButton";width:160;height:56;accent:true;enabled:!page.loading;text:page.selected.kind==="audio"?(page.backendAudio?"停止":"播放"):(videoLoader.item&&videoLoader.item.playing?"暂停":"播放");onClicked:{if(page.selected.kind==="audio"){if(page.backendAudio)page.stop();else page.playAudio();}else if(videoLoader.item){if(videoLoader.item.playing)videoLoader.item.pause();else videoLoader.item.play();}}}
            Button {width:96;height:56;text:"音＋";onClicked:page.volume=Math.min(1,page.volume+.1)}
        }
        Rectangle {x:30;y:159;width:740;height:7;visible:page.selected.kind==="audio";radius:3;color:Theme.button;Rectangle {height:7;radius:3;color:Theme.accent;width:page.duration()>0?parent.width*Math.min(1,page.position()/page.duration()):0}}
        Label {x:30;y:174;width:740;height:26;visible:page.selected.kind==="audio";text:"音量 "+Math.round(page.volume*100)+"%（下次播放生效）";font.pixelSize:20;color:Theme.secondary;horizontalAlignment:Text.AlignHCenter}
    }
    Item {
        x:18;y:0;width:parent.width-36;height:parent.height;visible:page.transferView
        Label {x:0;y:0;width:parent.width;height:34;text:page.transfer.enabled?"手机 / 电脑浏览器打开：":"同一可信局域网，手动开启，10 分钟有效";font.pixelSize:24;color:Theme.secondary}
        Label {x:0;y:38;width:parent.width;height:42;text:page.transfer.enabled?page.transfer.url:"只开放用户文件，不修改无线设置";font.pixelSize:30;color:Theme.accent}
        Label {x:0;y:80;width:parent.width;height:40;text:page.transfer.enabled?"访问码："+page.transfer.code+"    剩余 "+page.transfer.seconds+" 秒":"HTTP 无加密，请勿在公共 Wi-Fi 使用";font.pixelSize:page.transfer.enabled?28:24;color:page.transfer.enabled?"white":"#ffb06b"}
        Row {x:0;y:136;spacing:16
            Button {width:420;height:56;fontSize:24;text:page.addresses.length?(page.addresses[page.addressIndex%page.addresses.length].name+" · "+page.addresses[page.addressIndex%page.addresses.length].address):"未发现可用私网地址";enabled:!page.transfer.enabled&&page.addresses.length>1;onClicked:page.addressIndex++}
            Button {objectName:"transferToggle";width:220;height:56;accent:!page.transfer.enabled;text:page.transfer.enabled?"关闭传输":"开启传输";enabled:page.transfer.enabled||page.addresses.length>0;onClicked:{var path=page.transfer.enabled?"/api/transfer/stop":"/api/transfer/start",form=page.transfer.enabled?{stop:1}:{address:page.addresses[page.addressIndex%page.addresses.length].address};app.request(path,form,function(ok,d){if(ok)app.refresh();else app.toast(d.error);});}}
        }
    }
    Timer {
        interval:200;repeat:true;running:page.backendAudio&&page.audioGeneration>=0&&!page.leaving
        onTriggered:{if(page.audioPollPending)return;page.audioPollPending=true;app.request("/api/audio",null,function(ok,d){page.audioPollPending=false;if(ok&&d.generation===page.audioGeneration){if(Number(d.position_sample_monotonic_ms||0)!==Number(page.audioState.position_sample_monotonic_ms||0))page.sampleAt=Date.now();page.audioState=d;page.backendAudio=d.process_alive;if(d.status==="error")app.toast(d.error);}});}
    }
    Timer {interval:100;repeat:true;running:page.backendAudio;onTriggered:page.tick++}
    Component.onCompleted:load()
    Component.onDestruction:{invalidateOpen();if(!leaving){leaving=true;stop();}}
}
