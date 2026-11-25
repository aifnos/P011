import QtQuick 2.10
import QtQuick.Window 2.10
import QtTest 1.2
import "@@DEVICE_URL@@" as Toolbox

Rectangle {
    id:surface;width:800;height:480;color:"#000000"
    property bool done:false
    property string captureDirectory:"@@CAPTURE_DIR@@"
    Toolbox.MtaHost {
        id:app;x:0;y:106;width:800;height:268
        endpoint:"@@ENDPOINT@@";bootstrapAllowed:true
        onExitRequested:surface.done=true
    }
    TestCase {
        name:"P011MtaUi";when:windowShown
        function capture(name) {
            app.opacity=0.99;wait(120);app.opacity=1;wait(180);
            var picture=grabImage(app);compare(picture.width,800);compare(picture.height,268);
            picture.save(surface.captureDirectory+"/"+name+".png");
        }
        function test_no_radio_ui() {
            if(surface.Window.window) {
                surface.Window.window.flags=Qt.FramelessWindowHint;
                surface.Window.window.visibility=Window.FullScreen;
                surface.Window.window.requestActivate();
            }
            var page=findChild(app,"mtaPage");verify(page!==null);
            tryCompare(page,"backendOnline",true,7000);
            verify(!page.status.discoverable);verify(!page.status.scanning);
            capture("01-device-main-no-radio");
            app.fetchFiles("select");tryCompare(app,"message","",5000);
            compare(app.fileRows.length,1);compare(app.fileRows[0].size,16);
            var picker=findChild(app,"mtaFilePicker");verify(picker!==null);
            tryCompare(picker,"count",1,2000);
            mouseClick(picker,120,25);compare(app.picked.length,1);
            capture("02-device-file-selected");
            app.stage="mta";page.selectedFiles=app.picked;
            compare(page.selectedFiles.length,1);capture("03-device-selected-summary");
            var keyboard=findChild(app,"mtaKeyboard");verify(keyboard!==null);
            app.stage="keyboard";keyboard.open("P011 UI",false);wait(200);
            keyboard.key("X");compare(keyboard.value,"P011 UIX");
            capture("04-device-keyboard");keyboard.canceled();app.stage="mta";
            app.fetchFiles("received");tryCompare(app,"message","",5000);
            compare(app.fileRows.length,0);compare(app.stage,"files");verify(!keyboard.visible);
            capture("05-device-received-empty");
            app.stage="mta";verify(!page.status.discoverable);verify(!page.status.scanning);
            surface.done=true;
        }
    }
}
