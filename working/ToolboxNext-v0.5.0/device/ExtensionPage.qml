import QtQuick 2.10
Rectangle {
    id:root; objectName:"extensionPage"; color:"#10191f"
    property string endpoint:typeof nextEndpoint!=="undefined"?nextEndpoint:""
    property string token:typeof nextToken!=="undefined"?nextToken:""
    property string pageName:""; property string message:""; property var telemetry:({metrics:{},history:[],scores:{},transfer:{},addresses:[]})
    property var lifetime:({alive:true,epoch:0}); property var pending:[]; signal exitRequested()
    function request(path,form,done){
        var x=new XMLHttpRequest(),guard=lifetime,generation=guard.epoch,finished=false;
        function finish(ok,result){if(finished)return;finished=true;if(!guard.alive||guard.epoch!==generation)return;if(done)done(ok,result);}
        x.onreadystatechange=function(){if(x.readyState!==XMLHttpRequest.DONE)return;try{var o=JSON.parse(x.responseText);finish(x.status===200&&o.ok,o.ok?o.data:{error:o.error});}catch(e){finish(false,{error:"本地服务未就绪"});}};
        try{x.open(form===null?"GET":"POST",endpoint+path);x.setRequestHeader("X-P011-Token",token);var body="";if(form!==null){var fields=[];for(var k in form)fields.push(encodeURIComponent(k)+"="+encodeURIComponent(form[k]));body=fields.join("&");x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");}pending.push({xhr:x,at:Date.now(),finished:function(){return finished;},expire:function(){x.abort();finish(false,{error:"请求超时"});}});x.send(body);}catch(e){finish(false,{error:"本地服务连接失败"});}
    }
    function refresh(){request("/api/state",null,function(ok,d){if(ok)telemetry=d;else toast(d.error);});}
    function toast(text){message=text;toastTimer.restart();}
    function open(name){if(child.item&&child.item.prepareLeave)child.item.prepareLeave();lifetime.epoch++;pageName=name;child.setSource(name?Qt.resolvedUrl(name+"Page.qml"):"",name?{app:root}:{});refresh();}
    function back(){if(pageName)open("");else exitRequested();}
    function saveScore(game,score){request("/api/scores",{game:game,score:score},function(ok,d){if(ok){var t=telemetry;t.scores=d;telemetry=t;}else toast("最高分保存失败");});}
    Rectangle{height:42;width:parent.width;color:"#17252e"
        Button{x:8;y:4;width:84;height:34;text:"‹ 返回";onClicked:root.back()}
        Text{x:108;anchors.verticalCenter:parent.verticalCenter;color:"#f2faf8";font.pixelSize:22;text:root.pageName==="Files"?"文件中心":root.pageName==="Games"?"小游戏中心":root.pageName==="Dashboard"?"系统仪表盘":"工具箱 · 扩展中心"}
        Text{anchors.right:parent.right;anchors.rightMargin:14;anchors.verticalCenter:parent.verticalCenter;text:"v0.5 · 候选";color:"#65d8b9";font.pixelSize:16}
    }
    Row{x:14;y:68;spacing:12;visible:root.pageName===""
        Repeater{model:[{label:"文件中心",desc:"图片 · 文本 · 音视频\n局域网导入与导出",page:"Files",glyph:"▤"},{label:"小游戏中心",desc:"贪吃蛇 · 2048 · 打砖块\n暂停 · 最高分 · 快速退出",page:"Games",glyph:"▦"},{label:"系统仪表盘",desc:"CPU · 内存 · 网络速率\n只读进程 · 采样导出",page:"Dashboard",glyph:"▥"}]
            delegate:Rectangle{width:(root.width-52)/3;height:142;radius:10;color:area.pressed?"#26483f":"#1e303a"
                Canvas{x:18;y:20;width:28;height:26;onPaint:{var c=getContext("2d");c.strokeStyle="#6fe1be";c.lineWidth=2;c.strokeRect(2,2,23,21);if(index===0){for(var n=0;n<3;n++){c.beginPath();c.moveTo(7,7+n*5);c.lineTo(21,7+n*5);c.stroke();}}else if(index===1){c.beginPath();c.moveTo(14,2);c.lineTo(14,23);c.moveTo(2,12);c.lineTo(25,12);c.stroke();}else{c.beginPath();c.moveTo(6,18);c.lineTo(11,10);c.lineTo(16,14);c.lineTo(21,6);c.stroke();}}}
                Text{x:62;y:17;text:modelData.label;color:"#eef6f6";font.pixelSize:24}
                Text{x:17;y:67;width:parent.width-28;text:modelData.desc;color:"#a3bbc5";font.pixelSize:17;lineHeight:1.45}
                MouseArea{id:area;anchors.fill:parent;onClicked:root.open(modelData.page)}
            }
        }
    }
    Text{x:18;y:230;visible:root.pageName==="";text:"用户目录隔离 · 无线传输手动开启 · 不改原厂系统";color:"#8da7b4";font.pixelSize:16}
    Loader{id:child;objectName:"featureLoader";x:0;y:44;width:parent.width;height:parent.height-44;visible:root.pageName!=="";onStatusChanged:if(status===Loader.Error)root.toast("页面加载失败")}
    Rectangle{x:8;y:parent.height-39;width:parent.width-16;height:34;z:40;radius:6;visible:root.message!=="";color:"#e83d4b53";Text{anchors.fill:parent;anchors.margins:6;text:root.message;color:"white";font.pixelSize:16;elide:Text.ElideRight}MouseArea{anchors.fill:parent;onClicked:root.message=""}}
    Timer{id:toastTimer;interval:4000;onTriggered:root.message=""}
    Timer{objectName:"telemetryTimer";interval:2000;repeat:true;running:root.visible;onTriggered:root.refresh()}
    Timer{interval:500;repeat:true;running:true;onTriggered:{var keep=[];for(var i=0;i<root.pending.length;i++){var r=root.pending[i];if(r.finished())continue;if(Date.now()-r.at>6000)r.expire();else keep.push(r);}root.pending=keep;}}
    Keys.onEscapePressed:back()
    Component.onCompleted:refresh()
    Component.onDestruction:{lifetime.alive=false;for(var i=0;i<pending.length;i++)pending[i].xhr.abort();}
}
