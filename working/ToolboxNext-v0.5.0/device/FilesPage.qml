import QtQuick 2.10
Item {
    id:page;objectName:"filesPage";property var app;property string directory:"";property int offset:0;property int nextOffset:-1;property var entries:[];property var selected:({});property bool transferView:false;property int addressIndex:0;property bool loading:false;property var audioState:({});property double audioGeneration:-1;property bool audioPollPending:false;property bool backendAudio:false;property double sampleAt:0;property int tick:0;property double commandSerial:Date.now()*1000;property bool leaving:false
    property var transfer:app?app.telemetry.transfer:({});property var addresses:app?app.telemetry.addresses:[];property real volume:.25
    function load(){loading=true;app.request("/api/files?path="+encodeURIComponent(directory)+"&offset="+offset,null,function(ok,d){loading=false;if(ok){entries=d.entries;nextOffset=d.next===null?-1:d.next;if(d.limited)app.toast("目录超过 2000 项，请分目录保存");}else app.toast(d.error);});}
    function stop(){commandSerial++;if(backendAudio)app.request("/api/audio/stop",{command:commandSerial},null);backendAudio=false;audioGeneration=-1;audioState={};if(videoLoader.item)videoLoader.item.stop();videoLoader.source="";}
    function openFile(item){if(loading)return;if(item.kind==="directory"){directory=item.path;offset=0;load();return;}stop();loading=true;app.request("/api/open?path="+encodeURIComponent(item.path),null,function(ok,d){loading=false;if(!ok){app.toast(d.error);return;}selected=d;if(d.kind==="audio")playAudio();else if(d.kind==="video")videoLoader.setSource(Qt.resolvedUrl("VideoPane.qml"),{mediaUrl:d.url,volume:page.volume,app:app});});}
    function playAudio(){backendAudio=true;audioState={status:"starting",position_ms:0,duration_ms:0,process_alive:true};audioGeneration=-1;commandSerial++;loading=true;app.request("/api/audio/play",{path:selected.path,volume:Math.round(volume*100),command:commandSerial},function(ok,d){loading=false;if(ok){audioGeneration=d.generation;audioState=d;sampleAt=Date.now();}else{backendAudio=false;audioState={};app.toast(d.error);}});}
    function prepareLeave(){leaving=true;stop();}
    function stamp(ms){var s=Math.floor(Number(ms||0)/1000);return Math.floor(s/60)+":"+(s%60<10?"0":"")+s%60;}
    function position(){var t=tick;if(selected.kind!=="audio")return videoLoader.item?videoLoader.item.position:0;var p=Number(audioState.position_ms||0);if(audioState.status==="playing")p+=Math.max(0,Math.min(250,Date.now()-sampleAt));return Math.min(Number(audioState.duration_ms||p),p);}
    function duration(){return selected.kind==="audio"?Number(audioState.duration_ms||0):(videoLoader.item?videoLoader.item.duration:0);}
    onVolumeChanged:if(videoLoader.item)videoLoader.item.volume=volume
    Row{x:8;y:2;spacing:6
        Button{text:page.transferView?"文件列表":"无线传文件";width:128;accent:page.transferView;onClicked:{page.transferView=!page.transferView;if(page.transferView)page.stop();}}
        Button{text:"上一级";width:90;visible:!page.transferView;enabled:page.directory!==""&&!page.loading;onClicked:{page.directory=page.directory.split('/').slice(0,-1).join('/');page.offset=0;page.load();}}
        Button{text:"刷新";width:70;visible:!page.transferView;enabled:!page.loading;onClicked:page.load()}
        Text{width:360;height:36;verticalAlignment:Text.AlignVCenter;elide:Text.ElideMiddle;color:"#aac0c9";font.pixelSize:17;text:page.transferView?"只对同一可信局域网开放，10 分钟自动关闭":(page.directory||"用户目录")}
        Button{text:"下一页";width:88;visible:!page.transferView;enabled:page.nextOffset>=0&&!page.loading;onClicked:{page.offset=page.nextOffset;page.load();}}
    }
    Item{x:0;y:42;width:parent.width;height:parent.height-44;visible:!page.transferView
        Rectangle{x:8;width:280;height:parent.height;radius:6;color:"#192b35"
            ListView{objectName:"fileList";anchors.fill:parent;anchors.margins:4;model:page.entries;clip:true;spacing:3
                delegate:Rectangle{width:272;height:43;color:area.pressed?"#36594f":"#243844";radius:4
                    Text{x:8;y:3;width:255;text:(modelData.kind==="directory"?"> ":"")+modelData.name;color:"#eff7f4";font.pixelSize:18;elide:Text.ElideMiddle}
                    Text{x:8;y:26;width:255;text:modelData.kind==="directory"?"文件夹":modelData.kind+" · "+(modelData.bytes/1024).toFixed(1)+" KiB";color:"#8ba9b6";font.pixelSize:12}
                    MouseArea{id:area;anchors.fill:parent;enabled:!page.loading;onClicked:page.openFile(modelData)}
                }
            }
            Text{anchors.centerIn:parent;visible:page.entries.length===0;text:page.loading?"正在读取…":"暂无文件";color:"#a1b6c1";font.pixelSize:18}
        }
        Rectangle{x:298;width:parent.width-306;height:parent.height;color:"#0c141a";radius:6
            Text{x:8;y:4;width:parent.width-16;text:page.selected.path||"选择文件预览或播放";color:"#9cd8c7";font.pixelSize:16;elide:Text.ElideMiddle}
            Image{objectName:"imagePreview";x:8;y:27;width:parent.width-16;height:parent.height-32;visible:page.selected.kind==="image";source:visible?page.selected.url:"";sourceSize.width:1200;sourceSize.height:600;asynchronous:true;fillMode:Image.PreserveAspectFit;onStatusChanged:if(status===Image.Error)app.toast("图片无法解码")}
            Flickable{x:8;y:28;width:parent.width-16;height:parent.height-33;clip:true;visible:page.selected.kind==="text";contentHeight:bodyText.height
                Text{id:bodyText;objectName:"textPreview";width:parent.width;text:(page.selected.text||"")+(page.selected.truncated?"\n——仅预览前 64 KiB——":"");textFormat:Text.PlainText;wrapMode:Text.WrapAnywhere;color:"#e1ebec";font.pixelSize:18}
            }
            Item{anchors.fill:parent;anchors.topMargin:27;visible:page.selected.kind==="audio"||page.selected.kind==="video"
                Loader{id:videoLoader;anchors.fill:parent;anchors.bottomMargin:70;visible:page.selected.kind==="video";onStatusChanged:if(status===Loader.Error)app.toast("视频插件不可用，其他文件功能仍可使用")}
                Text{anchors.horizontalCenter:parent.horizontalCenter;y:8;visible:page.selected.kind==="audio";text:page.audioState.status==="starting"?"准备中…":"♫ 本地音乐";font.pixelSize:25;color:"#69d9b5"}
                Rectangle{x:8;y:parent.height-68;width:parent.width-16;height:5;color:"#304552";Rectangle{height:5;color:"#62d8b1";width:page.duration()>0?parent.width*Math.min(1,page.position()/page.duration()):0}}
                Text{x:8;y:parent.height-58;text:page.stamp(page.position())+" / "+page.stamp(page.duration())+"  音量 "+Math.round(page.volume*100)+"%";font.pixelSize:15;color:"#acc3ca"}
                Row{x:8;y:parent.height-35;spacing:8
                    Button{objectName:"mediaPlayButton";height:33;width:108;accent:true;enabled:!page.loading;text:page.selected.kind==="audio"?(page.backendAudio?"停止":"播放"):(videoLoader.item&&videoLoader.item.playing?"暂停":"播放");onClicked:{if(page.selected.kind==="audio"){if(page.backendAudio)page.stop();else page.playAudio();}else if(videoLoader.item){if(videoLoader.item.playing)videoLoader.item.pause();else videoLoader.item.play();}}}
                    Button{height:33;width:72;text:"音−";onClicked:page.volume=Math.max(0,page.volume-.1)}
                    Button{height:33;width:72;text:"音＋";onClicked:page.volume=Math.min(1,page.volume+.1)}
                    Text{height:33;verticalAlignment:Text.AlignVCenter;text:page.selected.kind==="audio"?"音量下次播放生效":"";color:"#809ba9";font.pixelSize:13}
                }
            }
            Text{anchors.centerIn:parent;visible:!page.selected.kind;text:"图片 / UTF-8 TXT / 音视频\n游戏资源仅保存，暂不执行";color:"#7e9ba9";font.pixelSize:20;horizontalAlignment:Text.AlignHCenter;lineHeight:1.5}
        }
    }
    Item{x:18;y:51;width:parent.width-36;height:parent.height-55;visible:page.transferView
        Text{x:0;y:0;width:parent.width;text:page.transfer.enabled?"手机或电脑浏览器打开：":"服务默认关闭。选择当前私网接口，再手动开启。";color:"#b1c4cd";font.pixelSize:18}
        Text{x:0;y:31;width:parent.width;text:page.transfer.enabled?page.transfer.url:"不会开启热点、修改 Wi-Fi 或开放蜂窝网络端口";color:"#73e0bf";font.pixelSize:25}
        Text{x:0;y:73;text:page.transfer.enabled?"访问码："+page.transfer.code+"    剩余 "+page.transfer.seconds+" 秒":"文件只保存在 /mnt/data/p011-user";color:"#eef8f5";font.pixelSize:24}
        Row{x:0;y:117;spacing:12
            Button{width:285;text:page.addresses.length?(page.addresses[page.addressIndex%page.addresses.length].name+" · "+page.addresses[page.addressIndex%page.addresses.length].address):"未发现可用私网地址";enabled:!page.transfer.enabled&&page.addresses.length>1;onClicked:page.addressIndex++}
            Button{objectName:"transferToggle";width:150;accent:!page.transfer.enabled;text:page.transfer.enabled?"关闭传输":"开启 10 分钟";enabled:page.transfer.enabled||page.addresses.length>0;onClicked:{var path=page.transfer.enabled?"/api/transfer/stop":"/api/transfer/start",form=page.transfer.enabled?{stop:1}:{address:page.addresses[page.addressIndex%page.addresses.length].address};app.request(path,form,function(ok,d){if(ok)app.refresh();else app.toast(d.error);});}}
        }
        Text{x:0;y:159;width:parent.width;text:"HTTP 无加密 · 不在公共 Wi-Fi 使用 · 离开此页服务仍按倒计时关闭";color:"#d9b184";font.pixelSize:15}
    }
    Timer{interval:200;repeat:true;running:page.backendAudio&&page.audioGeneration>=0&&!page.leaving;onTriggered:{if(page.audioPollPending)return;page.audioPollPending=true;app.request("/api/audio",null,function(ok,d){page.audioPollPending=false;if(ok&&d.generation===page.audioGeneration){if(Number(d.position_sample_monotonic_ms||0)!==Number(page.audioState.position_sample_monotonic_ms||0))page.sampleAt=Date.now();page.audioState=d;page.backendAudio=d.process_alive;if(d.status==="error")app.toast(d.error);}})}}
    Timer{interval:100;repeat:true;running:page.backendAudio;onTriggered:page.tick++}
    Component.onCompleted:load()
    Component.onDestruction:if(!leaving)stop()
}
