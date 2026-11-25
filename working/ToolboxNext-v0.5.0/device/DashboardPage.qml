import QtQuick 2.10
Item {
    id:page;objectName:"dashboardPage";property var app;property var metrics:app?app.telemetry.metrics:({});property var history:app?app.telemetry.history:[];property int networkIndex:0;property bool processView:false;property var processes:[]
    property var network:metrics.networks&&metrics.networks.length?metrics.networks[networkIndex%metrics.networks.length]:({})
    function size(value){if(value===null||value===undefined)return"未提供";return value>=1073741824?(value/1073741824).toFixed(2)+" GiB":value>=1048576?(value/1048576).toFixed(1)+" MiB":(value/1024).toFixed(1)+" KiB";}
    function number(value,suffix){return value===null||value===undefined?"未提供":Number(value).toFixed(1)+suffix;}
    function fetchProcesses(){app.request("/api/processes",null,function(ok,d){if(ok)processes=d.processes;else app.toast(d.error);});}
    Row{x:8;y:3;spacing:7
        Button{objectName:"processToggle";text:page.processView?"返回图表":"只读进程";width:116;onClicked:{page.processView=!page.processView;if(page.processView)page.fetchProcesses();}}
        Button{text:"导出采样";width:116;onClicked:app.request("/api/export",{what:"samples"},function(ok,d){app.toast(ok?"已保存到 "+d.path:d.error);})}
        Button{text:"导出日志";width:116;onClicked:app.request("/api/export",{what:"logs"},function(ok,d){app.toast(ok?"已保存到 "+d.path:d.error);})}
        Text{height:36;verticalAlignment:Text.AlignVCenter;text:page.metrics.uptime===null||page.metrics.uptime===undefined?"运行时间未提供":"已运行 "+Math.floor(page.metrics.uptime/3600)+" 时 "+Math.floor(page.metrics.uptime/60)%60+" 分";font.pixelSize:17;color:"#9cc8bc"}
    }
    Row{x:8;y:45;spacing:8;visible:!page.processView
        Repeater{model:[{name:"CPU",value:page.number(page.metrics.cpu_percent,"%")},{name:"内存占用",value:page.metrics.memory?page.size(page.metrics.memory.used):"未提供"},{name:"用户盘可用",value:page.metrics.storage?page.size(page.metrics.storage.available):"未提供"},{name:"网络 RX / TX",value:page.size(page.network.rx_per_second)+" / "+page.size(page.network.tx_per_second)+" /s"}]
            delegate:Rectangle{width:(page.width-40)/4;height:53;radius:6;color:"#1d303b";Text{x:9;y:5;text:modelData.name;color:"#8fadb9";font.pixelSize:14}Text{x:9;y:25;width:parent.width-15;text:modelData.value;color:"#8ce6c7";font.pixelSize:index===3?14:20;elide:Text.ElideRight}}
        }
    }
    Canvas{id:plot;objectName:"metricsPlot";x:8;y:105;width:parent.width-225;height:parent.height-112;visible:!page.processView
        onPaint:{var c=getContext("2d"),h=height,w=width;c.reset();c.fillStyle="#0b151c";c.fillRect(0,0,w,h);c.strokeStyle="#28404b";for(var j=1;j<4;j++){c.beginPath();c.moveTo(0,h*j/4);c.lineTo(w,h*j/4);c.stroke();}
            var samples=page.history.slice(-120),colors=["#5bdab0","#74abeb"];for(var series=0;series<2;series++){c.strokeStyle=colors[series];c.lineWidth=2;c.beginPath();var started=false;for(var i=0;i<samples.length;i++){var s=samples[i],v=series===0?s.cpu_percent:(s.memory&&s.memory.total&&s.memory.used!==null?100*s.memory.used/s.memory.total:null);if(v===null||v===undefined){started=false;continue;}var x=i*w/119,y=h-Math.min(100,Math.max(0,v))*h/100;if(started)c.lineTo(x,y);else{c.moveTo(x,y);started=true;}}c.stroke();}}}
    Column{x:parent.width-205;y:107;spacing:8;visible:!page.processView
        Row{spacing:10;Text{text:"CPU";font.pixelSize:16;color:"#5bdab0"}Text{text:"内存比例";font.pixelSize:16;color:"#74abeb"}}
        Button{width:195;height:34;text:"接口："+(page.network.name||"未提供");enabled:page.metrics.networks&&page.metrics.networks.length>1;onClicked:page.networkIndex++}
        Text{width:195;wrapMode:Text.Wrap;text:"约 2 秒采样 · 图表最近 120 点\n缺失值留空，不补成 0";font.pixelSize:14;color:"#849eaa"}
    }
    Item{x:8;y:46;width:parent.width-16;height:parent.height-52;visible:page.processView
        Row{spacing:10;Text{width:80;text:"PID";color:"#83d8bf";font.pixelSize:17}Text{width:370;text:"名称（不读取命令行参数）";color:"#83d8bf";font.pixelSize:17}Text{width:165;text:"常驻内存 / 状态";color:"#83d8bf";font.pixelSize:17}Button{height:27;width:110;text:"刷新";onClicked:page.fetchProcesses()}}
        ListView{objectName:"processList";x:0;y:34;width:parent.width;height:parent.height-34;model:page.processes;clip:true;spacing:3
            delegate:Rectangle{width:parent.width;height:30;color:index%2?"#172a35":"#20343e";Row{x:7;spacing:10;Text{width:80;text:modelData.pid;color:"#d8ece7";font.pixelSize:16}Text{width:370;text:modelData.name;color:"#d8ece7";font.pixelSize:16;elide:Text.ElideRight}Text{width:220;text:page.size(modelData.rss_bytes)+" / "+modelData.state;color:"#9abfc5";font.pixelSize:16}}}
        }
    }
    onHistoryChanged:plot.requestPaint()
}
