import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
import "qrc:/ZybQmlFiles/Funcs/UILogics.js" as UILogic
import "MenuCapture.js" as Capture
import "Api.js" as Api
Rectangle {
    id:toolbox;anchors.fill:parent;color:Style.mainbgColor;property string pageType:"p011toolbox"
    property string selectedTitle:"";property string selectedFile:"";property bool showingChild:child.source.toString().length>0
    property bool expanded:false;property bool online:false;property bool polling:false;property string apiError:"数据服务连接中"
    property var telemetry:({battery:{rows:[],history:[]},radio:{wifi:[],cell:[],bluetooth:[],errors:[],interfaces:[]},adb:{},ssh:{},media:[]})
    property string message:"";property bool captureBusy:false;property string captureLabel:"toolbox"
    property var pendingAction:null;property string confirmText:"";property bool confirmVisible:false;property int confirmDelay:0
    property var keyboardCallback:null;property var bookmarks:[{title:"示例网站",url:"https://example.com"}]
    function mark(s){console.log("P011_MENULAB_EVENT|"+Date.now()+"|"+s);}
    function toast(s){message=s;toastTimer.restart();}
    function refresh(periodic){if(periodic&&selectedFile==="MediaPage.qml"&&child.item&&child.item.backendAudio)return;if(polling)return;polling=true;Api.request("/api/state",null,function(ok,d){polling=false;online=ok;if(ok){telemetry=d;apiError="";}else apiError=d.error||"服务不可用";});}
    function action(name,callback){Api.request("/api/action",name,function(ok,d){mark("action_"+name+":"+(ok?"ok":"failed"));toast(ok?(d.message||"操作完成"):(d.error||"操作失败"));if(name.indexOf("media_play:")!==0)refresh();if(callback)callback(ok,d);});}
    function confirm(t,fn,delay){confirmText=t;pendingAction=fn;confirmDelay=delay||0;confirmVisible=true;}
    function editUrl(v,fn){keyboardCallback=fn;keyboard.show(v);}
    function noteAction(s){mark(s);scheduleCapture(s);}
    function scheduleCapture(label){captureLabel=label;captureDelay.restart();}
    function capturePage(manual){
        if(captureBusy||!visible||width<1||height<1)return;
        if(!manual&&selectedFile==="BrowserPage.qml"&&child.item&&child.item.internetEnabled){mark("capture_skipped:browser_privacy");return;}
        var n=Capture.reserve();if(!n)return;var fn=Date.now()+"-"+n+"-"+captureLabel.replace(/[^a-zA-Z0-9_-]/g,"_")+".png";captureBusy=true;
        try{if(!toolbox.grabToImage(function(result){var saved=false;try{saved=result.saveToFile("/mnt/data/p011-menu/_captures/"+fn);}catch(e){}captureBusy=false;mark((saved?"capture_saved:":"capture_failed:")+fn);})){captureBusy=false;mark("capture_not_started");}}
        catch(e){captureBusy=false;mark("capture_error");}
    }
    function openPage(title,file){selectedTitle=title;selectedFile=file;child.setSource(Qt.resolvedUrl(file), {"app": toolbox});}
    function goBack(){
        if(confirmVisible){confirmVisible=false;return;}if(keyboard.visible){keyboard.visible=false;return;}if(expanded){expanded=false;return;}
        mark(showingChild?"back_child":"back_home");
        if(showingChild){if(child.item&&child.item.prepareLeave)child.item.prepareLeave();child.source="";selectedTitle="";selectedFile="";scheduleCapture("toolbox");}
        else UILogic.backToHome();
    }
    Component.onCompleted:{mark("toolbox_ready");if(typeof devManager!=="undefined")mark("scan_mode:"+devManager.getScanForWhat());refresh();scheduleCapture("toolbox");}
    Component.onDestruction:mark("toolbox_destroyed")
    Timer{interval:350;running:true;onTriggered:{toolbox.mark("toolbox_layout:"+toolbox.width+"x"+toolbox.height+":children="+toolbox.children.length);if(toolbox.children.length<5)toolbox.mark("layout_error:missing_visual_children");}}
    Timer{interval:2000;repeat:true;running:toolbox.visible;onTriggered:toolbox.refresh(true)}
    Timer{id:toastTimer;interval:5000;onTriggered:toolbox.message=""}
    Timer{id:captureDelay;interval:650;onTriggered:toolbox.capturePage(false)}
    Timer{interval:15000;repeat:true;running:toolbox.visible;onTriggered:toolbox.scheduleCapture(toolbox.selectedTitle||"toolbox")}
    Rectangle{id:header;objectName:"toolbox-header";width:parent.width;height:toolbox.expanded?0:60;visible:!toolbox.expanded;color:Style.mainbgColor
        Image{x:18;y:8;width:44;height:44;source:"qrc:/images/back56x56.png";fillMode:Image.PreserveAspectFit;MouseArea{anchors.fill:parent;anchors.margins:-8;onClicked:toolbox.goBack()}}
        ToolText{anchors.centerIn:parent;text:toolbox.showingChild?toolbox.selectedTitle:"工具箱";font.pixelSize:30;font.bold:true}
        Rectangle{x:parent.width-152;y:25;width:8;height:8;radius:4;color:toolbox.online?Style.mainColor:Style.subColor}
        ToolButton{x:parent.width-134;y:8;width:114;text:"截屏";onClicked:{toolbox.captureLabel=toolbox.selectedFile||"toolbox";toolbox.capturePage(true);}}
    }
    Grid{objectName:"toolbox-grid";x:15;y:66;columns:3;columnSpacing:10;rowSpacing:10;visible:!toolbox.showingChild
        Repeater{model:[
            {title:"ADB 调试",file:"AdbPage.qml",icon:"qrc:/images/info42x42.png"},
            {title:"电池信息",file:"BatteryPage.qml",icon:"qrc:/images/light42x42.png"},
            {title:"无线电信息",file:"RadioPage.qml",icon:"qrc:/images/mobile42x42.png"},
            {title:"浏览器",file:"BrowserPage.qml",icon:"qrc:/images/set_main_wifi.png"},
            {title:"影音播放",file:"MediaPage.qml",icon:"qrc:/images/sound42x42.png"},
            {title:"SSH 连接",file:"SshPage.qml",icon:""}]
            delegate:Rectangle{objectName:"tool-card-"+index;width:(toolbox.width-50)/3;height:73;radius:6;color:hit.pressed?"#505158":"#303135"
                Image{x:18;anchors.verticalCenter:parent.verticalCenter;width:36;height:36;source:modelData.icon;fillMode:Image.PreserveAspectFit;visible:modelData.icon!==""}
                ToolText{x:15;width:46;height:40;anchors.verticalCenter:parent.verticalCenter;text:"SSH";font.pixelSize:17;color:Style.mainColor;visible:modelData.icon===""}
                ToolText{x:68;anchors.verticalCenter:parent.verticalCenter;width:parent.width-75;text:modelData.title;font.pixelSize:26}
                MouseArea{id:hit;anchors.fill:parent;onClicked:toolbox.openPage(modelData.title,modelData.file)}
            }
        }
    }
    ToolText{x:20;y:234;width:parent.width-40;height:26;visible:!toolbox.showingChild;text:toolbox.online?"测试版 · 10 分钟后恢复原厂 · 未提供的数据会明确标注":toolbox.apiError;color:toolbox.online?"#a0a2a8":Style.subColor;font.pixelSize:18}
    Loader{id:child;anchors.left:parent.left;anchors.right:parent.right;anchors.top:header.bottom;anchors.bottom:parent.bottom;visible:toolbox.showingChild
        onStatusChanged:{if(status===Loader.Ready){toolbox.mark("child_ready:"+toolbox.selectedFile);toolbox.scheduleCapture(toolbox.selectedFile);}
            if(status===Loader.Error){toolbox.mark("child_error:"+toolbox.selectedFile);source="";toolbox.expanded=false;toolbox.toast("页面加载失败，日志已保存，其他工具仍可使用");}}
    }
    Rectangle{anchors.left:parent.left;anchors.right:parent.right;anchors.bottom:parent.bottom;height:52;z:20;color:"#ee303135";visible:toolbox.message!==""
        ToolText{anchors.fill:parent;anchors.margins:8;text:toolbox.message;font.pixelSize:19;wrapMode:Text.Wrap;elide:Text.ElideNone}
        MouseArea{anchors.fill:parent;onClicked:toolbox.message=""}
    }
    Rectangle{anchors.fill:parent;z:90;visible:toolbox.confirmVisible;color:"#f50f0f0f";MouseArea{anchors.fill:parent}
        ToolText{x:30;y:14;width:parent.width-60;height:145;text:toolbox.confirmText;font.pixelSize:23;wrapMode:Text.Wrap;elide:Text.ElideNone}
        Row{anchors.horizontalCenter:parent.horizontalCenter;y:190;spacing:22
            ToolButton{text:"取消";width:150;onClicked:toolbox.confirmVisible=false}
            ToolButton{text:toolbox.confirmDelay>0?"请稍候 "+toolbox.confirmDelay:"确认";width:180;accent:true;enabled:toolbox.confirmDelay===0;onClicked:{toolbox.confirmVisible=false;var fn=toolbox.pendingAction;toolbox.pendingAction=null;if(fn)fn();}}
        }
        Timer{interval:1000;repeat:true;running:toolbox.confirmVisible&&toolbox.confirmDelay>0;onTriggered:toolbox.confirmDelay--}
    }
    KeyboardPanel{id:keyboard;anchors.fill:parent;z:100;onAccepted:if(toolbox.keyboardCallback)toolbox.keyboardCallback(value)}
}
