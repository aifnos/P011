import QtQuick 2.10
import "Theme.js" as Theme
Item {
    id:page;objectName:"dashboardPage";property var app
    property var metrics:app?app.telemetry.metrics:({})
    property var history:app?app.telemetry.history:[]
    property int networkIndex:0
    property string mode:"overview"
    property var processes:[]
    property var network:metrics.networks&&metrics.networks.length?metrics.networks[networkIndex%metrics.networks.length]:({})
    property string headerTitle:mode==="processes"?"只读进程":mode==="chart"?"系统曲线":mode==="export"?"导出记录":"系统仪表盘"
    property string headerAction:mode==="export"?"状态":"导出"
    function primaryAction(){mode=mode==="export"?"overview":"export";}
    function handleBack(){if(mode!=="overview"){mode="overview";return true;}return false;}
    function size(value){if(value===null||value===undefined)return"未提供";return value>=1073741824?(value/1073741824).toFixed(2)+" GiB":value>=1048576?(value/1048576).toFixed(1)+" MiB":(value/1024).toFixed(1)+" KiB";}
    function number(value,suffix){return value===null||value===undefined?"未提供":Number(value).toFixed(1)+suffix;}
    function fetchProcesses(){app.request("/api/processes",null,function(ok,d){if(ok)processes=d.processes;else app.toast(d.error);});}
    Grid {
        x:12;y:2;columns:2;spacing:10;visible:page.mode==="overview"
        Repeater {
            model:[{name:"CPU",value:page.number(page.metrics.cpu_percent,"%")},{name:"内存使用",value:page.metrics.memory?page.size(page.metrics.memory.used):"未提供"},
                   {name:"存储可用",value:page.metrics.storage?page.size(page.metrics.storage.available):"未提供"},{name:"网络 RX / TX",value:page.size(page.network.rx_per_second)+" / "+page.size(page.network.tx_per_second)+"/s"}]
            delegate:Rectangle {
                width:383;height:66;radius:6;color:Theme.row
                Label {x:16;y:4;width:350;height:26;text:modelData.name;font.pixelSize:20;color:Theme.secondary}
                Label {x:16;y:29;width:350;height:32;text:modelData.value;font.pixelSize:index===3?24:28;color:Theme.accent;elide:Text.ElideRight}
            }
        }
    }
    Row {x:12;y:151;spacing:12;visible:page.mode==="overview"
        Button {objectName:"chartToggle";width:142;height:48;text:"曲线";fontSize:24;onClicked:page.mode="chart"}
        Button {objectName:"processToggle";width:170;height:48;text:"只读进程";fontSize:24;onClicked:{page.mode="processes";page.fetchProcesses();}}
        Label {width:430;height:48;horizontalAlignment:Text.AlignRight;font.pixelSize:23;color:Theme.secondary;text:page.metrics.uptime===null||page.metrics.uptime===undefined?"运行时间未提供":"已运行 "+Math.floor(page.metrics.uptime/3600)+" 时 "+Math.floor(page.metrics.uptime/60)%60+" 分"}
    }
    Canvas {
        id:plot;objectName:"metricsPlot";x:12;y:5;width:parent.width-194;height:145;visible:page.mode==="chart"
        onPaint:{
            var c=getContext("2d"),h=height,w=width;c.reset();c.fillStyle="#191919";c.fillRect(0,0,w,h);c.strokeStyle="#3c3d42";
            for(var j=1;j<4;j++){c.beginPath();c.moveTo(0,h*j/4);c.lineTo(w,h*j/4);c.stroke();}
            var samples=page.history.slice(-120),colors=["#12cfa7","#00b9f5"];
            for(var series=0;series<2;series++){c.strokeStyle=colors[series];c.lineWidth=2;c.beginPath();var started=false;
                for(var i=0;i<samples.length;i++){var s=samples[i],v=series===0?s.cpu_percent:(s.memory&&s.memory.total&&s.memory.used!==null?100*s.memory.used/s.memory.total:null);
                    if(v===null||v===undefined){started=false;continue;}var x=i*w/119,y=h-Math.min(100,Math.max(0,v))*h/100;
                    if(started)c.lineTo(x,y);else{c.moveTo(x,y);started=true;}}c.stroke();}
        }
        onVisibleChanged:if(visible)requestPaint()
    }
    Column {x:parent.width-170;y:4;spacing:4;visible:page.mode==="chart"
        Label {text:"CPU  0–100%";font.pixelSize:22;color:Theme.accent}
        Label {text:"内存占比";font.pixelSize:22;color:"#00b9f5"}
        Label {width:158;text:"缺失采样留空";font.pixelSize:20;color:Theme.secondary}
    }
    Button {x:12;y:157;width:330;height:44;fontSize:22;visible:page.mode==="chart";text:"网络接口："+(page.network.name||"未提供");enabled:page.metrics.networks&&page.metrics.networks.length>1;onClicked:page.networkIndex++}
    Label {x:365;y:157;width:418;height:44;visible:page.mode==="chart";text:"约 2 秒采样 / 最近 120 点";font.pixelSize:22;color:Theme.secondary;horizontalAlignment:Text.AlignRight}
    Item {anchors.fill:parent;visible:page.mode==="processes"
        Row {x:14;y:0;spacing:10;Label {width:85;height:40;text:"PID";font.pixelSize:24;color:Theme.accent}Label {width:350;height:40;text:"进程名称";font.pixelSize:24;color:Theme.accent}Label {width:204;height:40;text:"内存 / 状态";font.pixelSize:24;color:Theme.accent}Button {height:40;width:100;text:"刷新";fontSize:22;onClicked:page.fetchProcesses()}}
        ListView {objectName:"processList";x:12;y:48;width:parent.width-24;height:parent.height-52;clip:true;spacing:4;model:page.processes
            delegate:Rectangle {width:776;height:48;radius:6;color:Theme.row
                Row {x:8;spacing:10;Label {width:85;height:48;text:modelData.pid;font.pixelSize:24}Label {width:350;height:48;text:modelData.name;font.pixelSize:24;elide:Text.ElideRight}Label {width:275;height:48;text:page.size(modelData.rss_bytes)+" / "+modelData.state;font.pixelSize:24;color:Theme.secondary}}
            }
        }
    }
    Item {anchors.fill:parent;visible:page.mode==="export"
        Label {x:18;y:3;width:764;height:40;text:"导出到文件中心 → 导出记录";font.pixelSize:28;color:Theme.secondary}
        Row {x:18;y:60;spacing:20
            Button {objectName:"exportSamples";width:330;height:64;text:"导出采样";accent:true;onClicked:app.request("/api/export",{what:"samples"},function(ok,d){app.toast(ok?"已保存采样记录":d.error);})}
            Button {width:330;height:64;text:"导出事件日志";onClicked:app.request("/api/export",{what:"logs"},function(ok,d){app.toast(ok?"已保存事件日志":d.error);})}
        }
        Label {x:18;y:143;width:764;height:48;text:"不读取命令行、环境变量或用户账号";font.pixelSize:24;color:Theme.secondary}
    }
    onHistoryChanged:plot.requestPaint()
}
