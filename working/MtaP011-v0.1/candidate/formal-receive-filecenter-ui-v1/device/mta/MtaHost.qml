import QtQuick 2.10
import "MtaTheme.js" as Theme

// One actual Receiver endpoint. File opening belongs to the attached
// FileCenter, never to /v1/files metadata or a synthetic second MTA Owner.
Rectangle {
    id:host;width:800;height:268;color:Theme.background
    property string endpoint:""
    property string accessToken:""
    property bool bootstrapAllowed:false
    property bool hostPreview:false
    property string stage:"mta"
    signal exitRequested()
    signal receivedDirectoryRequested()
    function suspendForLeave(){
        if(page)page.prepareLeave();
        if(board){board.generation++;board.visible=false;}
        stage="mta";
    }
    function resetHost(){suspendForLeave();}
    MtaPage {
        id:page;anchors.fill:parent;visible:host.stage==="mta"
        serviceUrl:host.endpoint;token:host.accessToken
        nicknameEditorAvailable:true;hostPreview:host.hostPreview
        onExitRequested:host.exitRequested()
        onFileCenterRequested:if(mode==="received")host.receivedDirectoryRequested()
        onNicknameEditRequested:{host.stage="keyboard";board.open(currentName,false);}
    }
    Item {
        anchors.fill:parent;visible:host.stage==="keyboard"
        // The reused board owns its own visible flag. Do not replace its
        // binding or leave a completed keyboard above the Receiver page.
        MtaKeyboard {
            id:board;objectName:"mtaKeyboard";anchors.fill:parent
            onAccepted:{page.applyNickname(value);host.stage="mta";}
            onCanceled:host.stage="mta"
            onNativeRequested:{chinese=false;page.toast("当前名称输入仅支持英文；可返回继续互传");}
        }
    }
}
