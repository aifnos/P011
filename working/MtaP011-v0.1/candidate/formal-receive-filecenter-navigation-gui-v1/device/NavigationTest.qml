// Candidate-only in-process input. No HTTP, RF, file opening or media call here.
import QtQuick 2.10
import QtQuick.Window 2.10
import QtTest 1.2 as Testing

Item {
    id:tester
    objectName:"receiveNavigationTesterV1"
    property var entryRoot:null
    property var observedWrapper:null
    property string phase:"ready"
    property bool done:false
    property double startedAt:Date.now()
    property double lastAt:startedAt
    property double phaseAt:startedAt
    property double stableAt:0
    property int ticks:0
    property int clicks:0
    property bool readyObserved:false
    property bool buttonReadyObserved:false
    property bool cancelObserved:false
    property bool freshStatusObserved:false
    property bool filesObserved:false
    property bool listingObserved:false
    property bool stableObserved:false
    property int listedGeneration:-1

    // Qt 5.10.1's plugin registers this native event type without qtestroot.
    // No TestCase, automatic test lifecycle, direct callbacks or Qt.quit().
    Testing.TestEvent {id:driver}

    function finish(passed,code){
        if(done)return;
        done=true;ticker.stop();
        if(!entryRoot||entryRoot.navigationTestTerminal)return;
        entryRoot.navigationTestTerminal=true;
        console.log("P011_MTA NAVIGATION_QTTEST_V1 "+JSON.stringify({schema:"navigation_qttest_v1",
            outcome:passed?"pass":"fail",code:code,ready_observed:readyObserved,
            button_ready_observed:buttonReadyObserved,click_count:clicks,
            cancel_confirmed_observed:cancelObserved,fresh_status_approved_observed:freshStatusObserved,
            files_page_observed:filesObserved,received_listing_observed:listingObserved,
            stable_observed:stableObserved,business_start_action_issued:false,
            file_opened:false,media_played:false,restoration_verified:false}));
    }
    function locate(name){
        if(!entryRoot||!entryRoot.navigationSurface)return null;
        var pending=[{item:entryRoot.navigationSurface,depth:0}],visited=0;
        while(pending.length>0&&visited<256){
            var row=pending.pop(),item=row.item;visited++;
            if(!item||row.depth>24)return null;
            if(item.objectName===name)return item;
            var children=item.children;
            if(!children)continue;
            if(children.length+visited+pending.length>256)return null;
            for(var i=children.length-1;i>=0;i--)pending.push({item:children[i],depth:row.depth+1});
        }
        return null;
    }
    function actualWindowVisible(){
        var window=tester.Window.window;
        return window!==null&&window.visible===true;
    }
    function usable(item){
        if(!item||item.visible!==true||item.enabled!==true||item.width<=0||item.height<=0)return false;
        var ancestor=item;
        for(var i=0;i<32&&ancestor;i++){
            if(ancestor.visible===false||ancestor.enabled===false||ancestor.opacity===0)return false;
            ancestor=ancestor.parent;
        }
        if(ancestor)return false;
        var point=item.mapToItem(entryRoot,item.width/2,item.height/2);
        return isFinite(point.x)&&isFinite(point.y)&&point.x>=0&&point.x<entryRoot.width&&
            point.y>=0&&point.y<entryRoot.height;
    }
    function originalIdle(page,wrapper){
        var value=page?page.status:null,network=value?value.networkRecovery:null;
        return page!==null&&wrapper!==null&&page.backendOnline===true&&page.tab==="receive"&&
            page.currentState==="idle"&&page.leaving===false&&page.actionPending===false&&
            page.radioBusy===false&&page.discoveryBusy===false&&page.hasRequest===false&&
            value!==null&&value.discoverable===false&&value.scanning===false&&value.restorePending===false&&
            !value.request&&(!network||(network.restorePending!==true&&network.recoveryLocked!==true))&&
            wrapper.exitPending===false&&wrapper.cancelIssued===false&&wrapper.cancelConfirmed===false;
    }
    function filesReady(){
        var surface=entryRoot.navigationSurface,loader=locate("featureLoader"),page=locate("filesPage");
        return surface!==null&&surface.pageName==="Files"&&loader!==null&&loader.status===Loader.Ready&&
            page!==null&&loader.item===page&&page.visible===true&&page.enabled===true&&
            page.directory==="Received"&&page.loading===false&&page.leaving===false&&
            page.navigationListingOK===true&&page.navigationListedGeneration===page.listingGeneration&&
            page.listingGeneration>0&&Array.isArray(page.entries)&&!page.selected.kind&&
            page.backendAudio===false&&page.transferView===false;
    }
    function step(){
        if(done)return;
        if(!entryRoot)return;
        if(entryRoot.navigationTestTerminal){done=true;ticker.stop();return;}
        var now=Date.now();ticks++;
        if(!isFinite(now)||now<lastAt){finish(false,"clock_unknown");return;}
        lastAt=now;
        if(ticks>180||now-startedAt>=18000){finish(false,"navigation_deadline");return;}
        if(entryRoot.failed||entryRoot.leaving||entryRoot.disposed){finish(false,"entry_unavailable");return;}
        if(phase==="ready"){
            if(entryRoot.readyLogged===true&&entryRoot.navigationSurface&&
                    entryRoot.navigationSurface.objectName==="formalReceiveFileCenterComposition"&&actualWindowVisible()){
                readyObserved=true;phase="button";phaseAt=now;
            }else if(now-startedAt>=6000)finish(false,"ready_timeout");
            return;
        }
        if(!actualWindowVisible()){finish(false,"window_hidden");return;}
        if(phase==="button"){
            var button=locate("mtaFiles"),page=locate("mtaPage"),wrapper=locate("mtaEmbedded");
            if(usable(button)&&originalIdle(page,wrapper)){
                observedWrapper=wrapper;buttonReadyObserved=true;clicks=1;phase="files";phaseAt=now;
                // One real click. Never emit clicked() or call a navigation/business function directly.
                // True only proves eventWindow existed, not that navigation completed.
                try{if(driver.mouseClick(button,button.width/2,button.height/2,Qt.LeftButton,Qt.NoModifier,10)!==true)finish(false,"click_failed");}
                catch(e){finish(false,"click_failed");}
            }else if(now-phaseAt>=3000)finish(false,"control_not_ready");
            return;
        }
        if(phase==="files"){
            // After approval the real Loader destroys MtaEmbedded. Do not
            // dereference that disposed object after copying its two events.
            if(!freshStatusObserved&&observedWrapper&&observedWrapper.cancelFailed){finish(false,"cancel_failed");return;}
            if(cancelObserved&&freshStatusObserved&&filesReady()){
                filesObserved=true;listingObserved=true;listedGeneration=locate("filesPage").listingGeneration;
                observedWrapper=null;stableAt=now;phase="stable";
            }else if(now-phaseAt>=8000)finish(false,"files_timeout");
            return;
        }
        if(phase==="stable"){
            if(!filesReady()||locate("filesPage").listingGeneration!==listedGeneration){finish(false,"files_not_stable");return;}
            if(now-stableAt>=750){stableObserved=true;finish(true,"received_page_stable");}
        }
    }
    Connections {
        target:tester.observedWrapper
        onCancelConfirmedChanged:{
            var wrapper=tester.observedWrapper;
            if(!tester.done&&tester.clicks===1&&wrapper&&wrapper.objectName==="mtaEmbedded"&&
                    wrapper.cancelIssued===true&&wrapper.cancelConfirmed===true&&wrapper.exitTarget==="Received")
                tester.cancelObserved=true;
        }
        onExitApprovedChanged:{
            var wrapper=tester.observedWrapper,value=wrapper?wrapper.lastStatus:null,network=value?value.networkRecovery:null;
            if(!tester.done&&tester.cancelObserved&&wrapper&&wrapper.exitApproved===true&&
                    wrapper.cancelConfirmed===true&&wrapper.exitTarget==="Received"&&wrapper.knownStatus===true&&
                    value&&value.state==="idle"&&value.discoverable===false&&value.scanning===false&&
                    value.restorePending===false&&!value.request&&
                    (!network||(network.restorePending!==true&&network.recoveryLocked!==true)))
                tester.freshStatusObserved=true;
        }
    }
    Timer {id:ticker;interval:100;repeat:true;running:tester.entryRoot!==null&&!tester.done;
        onTriggered:{try{tester.step();}catch(e){tester.finish(false,"tester_exception");}}}
    Component.onDestruction:if(!done&&entryRoot&&!entryRoot.navigationTestTerminal)finish(false,"tester_destroyed")
}
