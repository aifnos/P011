import QtQuick 2.10
import QtMultimedia 5.0
Item {
    id:pane;property var app;property url mediaUrl;property real volume:.25
    property int position:player.position;property int duration:player.duration;property bool playing:player.playbackState===MediaPlayer.PlayingState
    function play(){player.play();}function pause(){player.pause();}function stop(){player.stop();}
    MediaPlayer{id:player;source:pane.mediaUrl;volume:pane.volume;autoPlay:false;onError:if(pane.app)pane.app.toast("视频播放失败："+errorString)}
    VideoOutput{anchors.fill:parent;source:player;fillMode:VideoOutput.PreserveAspectFit}
    Component.onCompleted:player.play()
    Component.onDestruction:player.stop()
}
