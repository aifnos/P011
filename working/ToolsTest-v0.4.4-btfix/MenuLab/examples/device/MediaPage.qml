import QtQuick 2.10
import QtMultimedia 5.0
import "qrc:/ZybQmlFiles/Style"
import "Api.js" as Api
Item{
 id:page;property var app:null;property string filter:"all";property int currentIndex:-1;property string currentName:"未选择文件";property string currentKind:"";property int repeatMode:0;property string errorText:"";property bool backendAudio:false;property string audioStatus:"stopped";property real audioPositionAt:0;property int audioPositionBase:0;property int audioReportedPositionMs:0;property int audioDurationMs:0;property int audioGeneration:-1;property int audioRequestSerial:0;property int displayTick:0;property real audioLastSampleMonotonicMs:0;property int audioSyncLogs:0;property bool audioPollBusy:false;property var audioPollRequest:null
 property var entries:[]
 function updateFiles(){var source=app?app.telemetry.media:[],v=[];for(var i=0;i<source.length;i++)if(filter==="all"||source[i].kind===filter)v.push(source[i]);entries=v;}
 onAppChanged:updateFiles();onFilterChanged:updateFiles()
 Connections{target:app;ignoreUnknownSignals:true;onTelemetryChanged:page.updateFiles()}
 function cancelAudioPoll(){if(audioPollRequest)audioPollRequest.abort();audioPollRequest=null;audioPollBusy=false;}
 function pollAudio(){
  if(audioPollBusy||audioGeneration<0||!backendAudio)return;
  var request=audioRequestSerial;audioPollBusy=true;
  audioPollRequest=Api.request("/api/audio",null,function(ok,d){if(request!==audioRequestSerial)return;audioPollBusy=false;audioPollRequest=null;if(ok)page.syncAudio(d);else page.errorText=d.error||"读取音频状态失败";});
 }
 function syncAudio(s){
  if(audioGeneration<0||s.generation!==audioGeneration)return;
  var now=Date.now(),status=String(s.status||"starting"),changed=status!==audioStatus;
  var sampleMonotonic=Number(s.position_sample_monotonic_ms||0),position=Math.max(0,Number(s.position_ms||0));
  var sampleEpoch=Number(s.position_sample_epoch_ms||0),age=sampleEpoch>0?Math.max(0,Math.min(250,now-sampleEpoch)):0;
  audioDurationMs=Math.max(0,Number(s.duration_ms||audioDurationMs));
  if(sampleMonotonic>audioLastSampleMonotonicMs||status==="ended"||status==="error"){
   var next=position+(status==="playing"?age:0);
   if(status==="playing")next=Math.min(position+250,Math.max(shownPosition(),next));
   audioReportedPositionMs=position;audioPositionBase=Math.round(audioDurationMs>0?Math.min(audioDurationMs,next):next);audioPositionAt=now;audioLastSampleMonotonicMs=sampleMonotonic;
  }
  if(status==="starting"&&audioLastSampleMonotonicMs===0){audioPositionBase=0;audioPositionAt=0;}
  audioStatus=status;backendAudio=!!s.process_alive;
  if(status==="error")errorText=s.error||"音频后端提前退出";
  if((audioSyncLogs<12||changed)&&app){app.mark("audio_position_sync:g="+audioGeneration+":status="+status+":raw="+Math.round(position)+":age="+Math.round(age)+":after="+audioPositionBase);audioSyncLogs++;}
 }
 function stamp(n){n=Math.floor(n/1000);return Math.floor(n/60)+":"+(n%60<10?"0":"")+(n%60);}
 function playIndex(i){if(entries.length===0)return;i=(i+entries.length)%entries.length;currentIndex=i;currentName=entries[i].name;currentKind=entries[i].kind;errorText="";player.stop();var request=++audioRequestSerial;cancelAudioPoll();if(entries[i].kind==="audio"){player.source="";audioPositionAt=0;audioPositionBase=0;audioDurationMs=0;audioGeneration=-1;audioLastSampleMonotonicMs=0;audioSyncLogs=0;audioStatus="starting";backendAudio=true;if(app)app.action("media_play:"+entries[i].id+":"+Math.round(player.volume*100),function(ok,d){if(request!==audioRequestSerial)return;if(!ok){backendAudio=false;audioStatus="error";errorText=d.error||"音频播放失败";}else{audioGeneration=d.generation;page.syncAudio(d);page.pollAudio();}});}else{backendAudio=false;audioStatus="stopped";audioGeneration=-1;audioDurationMs=0;if(app)app.action("media_stop");player.source=entries[i].url;player.play();}if(app)app.noteAction("media_select:"+entries[i].kind);}
 function shownPosition(){if(currentKind!=="audio")return player.position;var tick=displayTick,ms=audioPositionBase,d=shownDuration();if(backendAudio&&audioStatus==="playing"&&audioPositionAt>0)ms=Math.min(audioReportedPositionMs+250,ms+Math.max(0,Math.min(250,Date.now()-audioPositionAt)));return d>0?Math.min(d,ms):ms;}
 function shownDuration(){return currentKind==="audio"?audioDurationMs:player.duration;}
 function changeVolume(delta){player.volume=Math.max(0,Math.min(1,player.volume+delta));if(backendAudio)playIndex(currentIndex);}
 function stopAudio(){audioRequestSerial++;cancelAudioPoll();if(currentKind==="audio"&&app)app.action("media_stop");audioStatus="stopped";backendAudio=false;audioGeneration=-1;audioLastSampleMonotonicMs=0;audioPositionAt=0;audioPositionBase=0;audioDurationMs=0;}
 function prepareLeave(){player.stop();stopAudio();if(app)app.expanded=false;}
 Timer{interval:200;repeat:true;running:page.currentKind==="audio"&&page.backendAudio;onTriggered:page.pollAudio()}
 Timer{interval:100;repeat:true;running:page.currentKind==="audio"&&page.backendAudio;onTriggered:page.displayTick++}
 MediaPlayer{
  id:player;autoPlay:false;volume:.25
  onError:{page.errorText=errorString;if(app)app.mark("media_error:"+error);}
  onPlaybackStateChanged:if(app)app.noteAction("media_state:"+playbackState)
  onStatusChanged:{if(status===MediaPlayer.EndOfMedia){if(page.repeatMode===1){seek(0);play();}else if(page.repeatMode===2)page.playIndex(page.currentIndex+1);}}
 }
 Rectangle{id:library;x:10;y:3;width:272;height:parent.height-8;visible:!app||!app.expanded;color:"#17181a";radius:6
  Row{x:5;y:5;spacing:4
   ToolButton{text:"全部";width:60;height:34;accent:page.filter==="all";onClicked:page.filter="all"}
   ToolButton{text:"音频";width:60;height:34;accent:page.filter==="audio";onClicked:page.filter="audio"}
   ToolButton{text:"视频";width:60;height:34;accent:page.filter==="video";onClicked:page.filter="video"}
   ToolButton{text:"刷新";width:60;height:34;onClicked:if(app)app.action("media_refresh")}
  }
  ListView{x:5;y:45;width:parent.width-10;height:parent.height-48;model:page.entries;clip:true;spacing:3
   delegate:Rectangle{width:262;height:55;radius:4;color:page.currentIndex===index?"#224c41":"#303135"
    ToolText{x:9;y:2;width:245;height:29;text:modelData.name;font.pixelSize:20}
    ToolText{x:9;y:29;width:245;height:22;text:(modelData.kind==="audio"?"音频":"视频")+" · "+(modelData.bytes/1048576).toFixed(2)+" MiB";font.pixelSize:16;color:"#a8abb2"}
    MouseArea{anchors.fill:parent;onClicked:page.playIndex(index)}
   }
  }
 }
 Item{id:viewer;x:app&&app.expanded?0:292;width:parent.width-x;height:parent.height
  Rectangle{anchors.fill:parent;color:"black"}
  VideoOutput{id:output;source:player;anchors.fill:parent;anchors.bottomMargin:app&&app.expanded?0:100;fillMode:VideoOutput.PreserveAspectFit}
  ToolText{anchors.centerIn:output;width:parent.width-30;horizontalAlignment:Text.AlignHCenter;text:player.hasVideo?"":(page.currentName==="未选择文件"?"选择左侧文件开始播放":"♫  "+page.currentName);font.pixelSize:26;color:Style.mainColor;wrapMode:Text.Wrap;elide:Text.ElideNone}
  ToolButton{x:8;y:4;width:78;height:34;text:player.playbackRate.toFixed(2)+"×";enabled:page.currentKind!=="audio";onClicked:{var rates=[.75,1,1.25,1.5,2],n=rates.indexOf(player.playbackRate);player.playbackRate=rates[(n+1)%rates.length];}}
  ToolButton{x:parent.width-83;y:4;width:78;height:34;text:app&&app.expanded?"还原":"展开";onClicked:if(app)app.expanded=!app.expanded}
  Rectangle{x:8;y:parent.height-98;width:parent.width-16;height:8;radius:4;color:"#44464e"
   Rectangle{width:page.shownDuration()>0?parent.width*Math.max(0,Math.min(1,page.shownPosition()/page.shownDuration())):0;height:parent.height;color:Style.mainColor;radius:4}
   MouseArea{anchors.fill:parent;anchors.topMargin:-9;anchors.bottomMargin:-9;enabled:page.currentKind!=="audio";onReleased:if(player.seekable){player.seek(player.duration*Math.max(0,Math.min(1,mouse.x/width)));if(app)app.mark("media_seek");}}
  }
  ToolText{x:10;y:parent.height-84;width:parent.width-20;height:24;text:(page.currentKind==="audio"&&page.audioStatus==="starting"?"准备中 ":"")+page.stamp(page.shownPosition())+" / "+page.stamp(page.shownDuration())+"    音量 "+Math.round(player.volume*100)+"%";font.pixelSize:17;color:"#b6b8c0"}
  Row{x:8;y:parent.height-55;spacing:6
   ToolButton{text:"上一首";width:80;height:39;enabled:page.entries.length>0;onClicked:page.playIndex(page.currentIndex-1)}
   ToolButton{text:backendAudio?"停止":player.playbackState===MediaPlayer.PlayingState?"暂停":"播放";width:82;height:39;accent:true;onClicked:{if(backendAudio)page.stopAudio();else if(player.playbackState===MediaPlayer.PlayingState)player.pause();else if(player.source.toString())player.play();else page.playIndex(currentIndex>=0?currentIndex:0);}}
   ToolButton{text:"下一首";width:80;height:39;enabled:page.entries.length>0;onClicked:page.playIndex(page.currentIndex+1)}
   ToolButton{text:page.repeatMode===0?"单次":page.repeatMode===1?"单曲":"列表";width:68;height:39;enabled:page.currentKind!=="audio";onClicked:page.repeatMode=(page.repeatMode+1)%3}
   ToolButton{text:"音−";width:64;height:39;onClicked:page.changeVolume(-.1)}
   ToolButton{text:"音＋";width:64;height:39;onClicked:page.changeVolume(.1)}
  }
 }
 Rectangle{anchors.left:parent.left;anchors.right:parent.right;anchors.bottom:parent.bottom;height:58;z:5;color:"#f03c3d42";visible:page.errorText!==""
  ToolText{anchors.fill:parent;anchors.margins:7;text:page.errorText;wrapMode:Text.Wrap;elide:Text.ElideNone;font.pixelSize:19}
  MouseArea{anchors.fill:parent;onClicked:page.errorText=""}
 }
 Component.onDestruction:{player.stop();stopAudio();}
}
