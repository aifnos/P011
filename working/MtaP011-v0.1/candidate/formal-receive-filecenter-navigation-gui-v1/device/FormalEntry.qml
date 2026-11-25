// One actual Receiver Owner and its attached FileCenter; no synthetic credentials.
import QtQuick 2.10
Rectangle {
    id:entry;width:800;height:268;color:"#101115"
    readonly property string sessionId:"@SESSION@"
    readonly property string credentialsUrl:"file://@REMOTE@/credentials.json"
    property var request:null
    property bool disposed:false
    property bool leaving:false
    property bool failed:false
    property bool readyLogged:false
    // Explicit candidate-only argv opt-in. Empty source means QtTest is not imported.
    readonly property bool navigationQtTestRequested:Qt.application.arguments.indexOf("--p011-mta-navigation-qt-test-v1")>=0
    readonly property var navigationSurface:surface.item
    property bool navigationTestTerminal:false
    function navigationTestFailure(code){
        if(!navigationQtTestRequested||navigationTestTerminal)return;
        navigationTestTerminal=true;
        console.log("P011_MTA NAVIGATION_QTTEST_V1 "+JSON.stringify({schema:"navigation_qttest_v1",outcome:"fail",code:code,
            ready_observed:false,button_ready_observed:false,click_count:0,cancel_confirmed_observed:false,
            fresh_status_approved_observed:false,files_page_observed:false,received_listing_observed:false,
            stable_observed:false,business_start_action_issued:false,file_opened:false,media_played:false,restoration_verified:false}));
    }
    property string message:"正在连接互传与文件中心"
    function endpointValid(value){var row=typeof value==="string"?/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(value):null;return row!==null&&Number(row[1])<=65535;}
    function abortCredentials(){readDeadline.stop();if(request){var old=request;request=null;old.onreadystatechange=function(){};old.abort();}}
    function failClosed(){if(disposed||leaving||failed)return;failed=true;abortCredentials();surface.active=false;message="本地服务未就绪，请返回后重试";console.log("P011_MTA FORMAL_UI_FAILED");}
    function leave(){if(disposed||leaving)return;leaving=true;abortCredentials();surface.active=false;message="正在结束互传";console.log("P011_MTA FORMAL_UI_EXIT_REQUESTED");Qt.quit();}
    function ready(){if(readyLogged||disposed||leaving||failed)return;readyLogged=true;message="";console.log("P011_MTA FORMAL_UI_READY");}
    function readCredentials(){
        if(disposed||leaving||failed||request)return;
        var xhr=new XMLHttpRequest();request=xhr;
        xhr.onreadystatechange=function(){
            if(disposed||leaving||failed||request!==xhr||xhr.readyState!==XMLHttpRequest.DONE)return;
            request=null;
            if((xhr.status!==0&&xhr.status!==200)||xhr.responseText.length<1||xhr.responseText.length>1024){failClosed();return;}
            var value;try{value=JSON.parse(xhr.responseText);}catch(e){failClosed();return;}
            if(!value||value.session!==sessionId||!endpointValid(value.endpoint)||!endpointValid(value.toolboxEndpoint)||value.endpoint===value.toolboxEndpoint||
                    typeof value.token!=="string"||!/^[0-9a-f]{64}$/.test(value.token)||
                    typeof value.toolboxToken!=="string"||!/^[0-9a-f]{64}$/.test(value.toolboxToken)||value.token===value.toolboxToken){failClosed();return;}
            surface.setSource(Qt.resolvedUrl("ReceiveComposition.qml"),{endpoint:value.toolboxEndpoint,token:value.toolboxToken,
                mtaServiceUrl:value.endpoint,mtaAccessToken:value.token,bootstrapAllowed:false,mtaBootstrapAllowed:false,hostPreview:false});
            value=null;
        };
        readDeadline.start();try{xhr.open("GET",credentialsUrl);xhr.send();}catch(e){failClosed();}
    }
    Loader {id:surface;anchors.fill:parent;asynchronous:false;onStatusChanged:if(status===Loader.Error)entry.failClosed()}
    Connections {target:surface.item;onExitRequested:entry.leave();onCompositionReady:{readDeadline.stop();entry.ready();}}
    Text {anchors.centerIn:parent;width:720;height:92;visible:!entry.readyLogged;text:entry.message;color:"#a7a9b7";font.pixelSize:24;horizontalAlignment:Text.AlignHCenter;verticalAlignment:Text.AlignVCenter;wrapMode:Text.Wrap}
    Rectangle {x:288;y:192;width:224;height:62;radius:10;color:pointer.pressed?"#30323d":"#242630";visible:entry.failed&&!entry.leaving
        Text {anchors.fill:parent;text:"返回";color:"white";font.pixelSize:24;horizontalAlignment:Text.AlignHCenter;verticalAlignment:Text.AlignVCenter}
        MouseArea {id:pointer;anchors.fill:parent;onClicked:entry.leave()}}
    Timer {id:readDeadline;interval:6000;repeat:false;onTriggered:entry.failClosed()}
    Timer {interval:40;repeat:true;running:!entry.readyLogged&&!entry.failed&&!entry.leaving;onTriggered:if(surface.item&&surface.item.compositionLoaded===true){readDeadline.stop();entry.ready();}}
    Keys.onEscapePressed:{if(surface.item&&surface.item.requestExit)surface.item.requestExit();else entry.leave();}
    Loader {
        id:navigationTester;anchors.fill:parent;asynchronous:false
        active:entry.navigationQtTestRequested
        source:active?Qt.resolvedUrl("NavigationTest.qml"):""
        onLoaded:item.entryRoot=entry
        onStatusChanged:if(status===Loader.Error)entry.navigationTestFailure("tester_import_failed")
    }
    Timer {
        interval:18000;repeat:false;running:entry.navigationQtTestRequested&&!entry.navigationTestTerminal
        onTriggered:{if(navigationTester.item&&navigationTester.item.finish)navigationTester.item.finish(false,"entry_deadline");else entry.navigationTestFailure("tester_unavailable");}
    }
    Component.onCompleted:readCredentials()
    Component.onDestruction:{disposed=true;abortCredentials();surface.active=false;}
}
