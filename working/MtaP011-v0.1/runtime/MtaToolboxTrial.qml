import QtQuick 2.10
import QtQuick.Window 2.10
import QtTest 1.2
import "@@TOOLBOX_URL@@" as Toolbox

Rectangle {
    id:surface;width:800;height:480;color:"#000000"
    property bool done:false
    property string captureDirectory:"@@CAPTURE_DIR@@"
    Toolbox.ExtensionPage {
        id:app;x:0;y:106;width:800;height:268
        endpoint:"@@TOOLBOX_ENDPOINT@@";token:"@@TOOLBOX_TOKEN@@"
        mtaServiceUrl:"@@MTA_ENDPOINT@@";mtaAccessToken:"@@MTA_TOKEN@@"
        onExitRequested:surface.done=true
    }
    TestCase {
        name:"P011ToolboxMtaUi";when:windowShown
        function capture(name) {
            app.opacity=0.99;wait(120);app.opacity=1;wait(180);
            var picture=grabImage(app);compare(picture.width,800);compare(picture.height,268);
            picture.save(surface.captureDirectory+"/"+name+".png");
        }
        function test_integrated_no_radio_ui() {
            if(surface.Window.window) {
                surface.Window.window.flags=Qt.FramelessWindowHint;
                surface.Window.window.visibility=Window.FullScreen;
                surface.Window.window.requestActivate();
            }
            tryCompare(app,"connected",true,5000);
            var heading=findChild(app,"toolboxHeaderTitle");verify(heading!==null);
            compare(heading.text,"工具箱");
            capture("01-toolbox-home");
            var loader=findChild(app,"featureLoader");verify(loader!==null);
            app.open("Files");tryCompare(app,"pageName","Files",3000);
            tryVerify(function(){return loader.item!==null;},3000);
            compare(loader.y,64);compare(loader.height,204);
            capture("02-toolbox-files");
            app.openReceivedDirectory();
            tryVerify(function(){return loader.item&&loader.item.directory==="Received"&&loader.item.entries.length===1;},5000);
            var size=findChild(loader.item,"fileEntrySize0");verify(size!==null);
            verify(size.text.indexOf("16 B")>=0);
            capture("03-toolbox-received");
            app.open("Mta");tryCompare(app,"pageName","Mta",3000);
            tryVerify(function(){return loader.item&&loader.item.host&&loader.item.knownStatus;},7000);
            var wrapper=loader.item,host=wrapper.host,page=findChild(host,"mtaPage");
            verify(page!==null);tryCompare(page,"backendOnline",true,5000);
            compare(loader.y,0);compare(loader.height,268);compare(wrapper.width,800);
            verify(!page.status.discoverable);verify(!page.status.scanning);
            verify(!page.capability("receive"));verify(!page.capability("send"));
            capture("04-toolbox-mta");
            host.fetchFiles("select");tryCompare(host,"message","",5000);
            compare(host.fileRows.length,2);host.choose(host.fileRows[0]);compare(host.picked.length,1);
            capture("05-toolbox-file-picker");
            host.stage="mta";page.selectedFiles=host.picked;
            var keyboard=findChild(host,"mtaKeyboard");verify(keyboard!==null);
            host.stage="keyboard";keyboard.open("P011 UI",false);wait(200);
            capture("06-toolbox-keyboard");
            mouseClick(keyboard,671,23);tryCompare(host,"stage","mta",2000);verify(!keyboard.visible);
            host.fetchFiles("received");tryCompare(host,"message","",5000);compare(host.fileRows.length,1);
            capture("07-toolbox-mta-received");
            wrapper.requestExit();tryCompare(app,"pageName","",7000);
            tryCompare(heading,"text","工具箱",2000);
            capture("08-toolbox-returned-home");
            surface.done=true;
        }
    }
}
