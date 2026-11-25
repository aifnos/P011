import QtQuick 2.10
import "Games.js" as Rules
Item {
    id:page;objectName:"gamesPage";property var app;property string game:"snake";property var state:Rules.newSnake(Math.random);property bool paused:true;property double lastTick:0;property int best:app&&app.telemetry.scores?Number(app.telemetry.scores[game]||0):0
    function persist(){if(app)app.saveScore(game,Number(state.score||0));}
    function start(name){persist();game=name;paused=true;state=game==="snake"?Rules.newSnake(Math.random):game==="2048"?Rules.new2048(Math.random):Rules.newBricks();field.requestPaint();forceActiveFocus();}
    function prepareLeave(){paused=true;persist();}
    function move(direction){if(paused||state.over)return;if(game==="snake")state=Rules.turnSnake(state,direction);else if(game==="2048"){state=Rules.slide2048(state,direction,Math.random);if(state.over)persist();}else if(direction==="left"||direction==="right")state.paddle=Math.max(40,Math.min(560,state.paddle+(direction==="left"?-35:35)));field.requestPaint();}
    function tick(){if(paused||state.over)return;state=game==="snake"?Rules.tickSnake(state,Math.random):Rules.tickBricks(state,0.032);if(state.over){paused=true;persist();}field.requestPaint();}
    Row{x:8;y:3;spacing:7
        Button{objectName:"snakeButton";text:"贪吃蛇";width:96;accent:page.game==="snake";onClicked:page.start("snake")}
        Button{objectName:"mergeButton";text:"2048";width:80;accent:page.game==="2048";onClicked:page.start("2048")}
        Button{objectName:"bricksButton";text:"打砖块";width:96;accent:page.game==="bricks";onClicked:page.start("bricks")}
        Button{objectName:"pauseButton";text:page.paused?"开始 / 继续":"暂停";width:124;enabled:!page.state.over;onClicked:{page.paused=!page.paused;if(page.paused)page.persist();page.forceActiveFocus();field.requestPaint();}}
        Button{text:"重来";width:78;onClicked:page.start(page.game)}
        Text{height:36;verticalAlignment:Text.AlignVCenter;text:"分数 "+page.state.score+"  /  最高 "+Math.max(page.best,page.state.score);font.pixelSize:17;color:"#98dbcb"}
    }
    Canvas{id:field;objectName:"gameCanvas";x:10;y:45;width:parent.width-128;height:parent.height-51
        onPaint:{var c=getContext("2d"),s=page.state,w=width,h=height;c.reset();c.fillStyle="#0b1218";c.fillRect(0,0,w,h);
            if(page.game==="snake"){var size=Math.min(w/s.w,h/s.h);c.fillStyle="#f59d69";c.fillRect((s.food%s.w)*size+2,Math.floor(s.food/s.w)*size+2,size-4,size-4);for(var i=0;i<s.body.length;i++){c.fillStyle=i===0?"#b4ffb3":"#44c9a0";c.fillRect((s.body[i]%s.w)*size+1,Math.floor(s.body[i]/s.w)*size+1,size-2,size-2);}}
            else if(page.game==="2048"){var size2=Math.min(h,w)/4,ox=(w-size2*4)/2;for(var j=0;j<16;j++){var n=s.cells[j];c.fillStyle=n?"hsl("+(160-Math.log(n)/Math.LN2*9)+",48%,"+(25+Math.min(32,Math.log(n)/Math.LN2*3))+"%)":"#263944";c.fillRect(ox+(j%4)*size2+2,Math.floor(j/4)*size2+2,size2-4,size2-4);if(n){c.fillStyle="#fff";c.font="bold "+(n>999?17:22)+"px sans-serif";c.textAlign="center";c.textBaseline="middle";c.fillText(String(n),ox+(j%4+0.5)*size2,(Math.floor(j/4)+0.5)*size2);}}}
            else{c.save();c.scale(w/600,h/190);for(var b=0;b<24;b++)if(s.blocks[b]){c.fillStyle=["#51d6b1","#6baad1","#ddaf68"][Math.floor(b/8)];c.fillRect(8+b%8*74,12+Math.floor(b/8)*22,68,16);}c.fillStyle="#e7faff";c.beginPath();c.arc(s.x,s.y,5,0,Math.PI*2);c.fill();c.fillStyle="#78ebc8";c.fillRect(s.paddle-40,166,80,7);c.restore();}
            if(page.paused||s.over){c.fillStyle="#bb10191f";c.fillRect(0,h/2-24,w,48);c.fillStyle="#fff";c.font="20px sans-serif";c.textAlign="center";c.textBaseline="middle";c.fillText(s.over?(s.won?"完成！点击重来":"本局结束 · 点击重来"):"已暂停 · 点击开始 / 继续",w/2,h/2);}}
        MouseArea{anchors.fill:parent;property real startX:0;property real startY:0;onPressed:{startX=mouse.x;startY=mouse.y;if(page.game==="bricks"&&!page.paused){page.state.paddle=Math.max(40,Math.min(560,mouse.x/width*600));field.requestPaint();}}onPositionChanged:if(pressed&&page.game==="bricks"&&!page.paused){page.state.paddle=Math.max(40,Math.min(560,mouse.x/width*600));field.requestPaint();}onReleased:{var dx=mouse.x-startX,dy=mouse.y-startY;if(Math.max(Math.abs(dx),Math.abs(dy))>18)page.move(Math.abs(dx)>Math.abs(dy)?(dx>0?"right":"left"):(dy>0?"down":"up"));}}
    }
    Column{x:parent.width-108;y:52;spacing:7
        Button{text:"↑";visible:page.game!=="bricks";width:98;height:36;onClicked:page.move("up")}
        Row{spacing:4;Button{text:"←";width:47;height:36;onClicked:page.move("left")}Button{text:"→";width:47;height:36;onClicked:page.move("right")}}
        Button{text:"↓";visible:page.game!=="bricks";width:98;height:36;onClicked:page.move("down")}
        Text{width:98;text:page.game==="bricks"?"拖动挡板":"支持滑动";color:"#94adb8";horizontalAlignment:Text.AlignHCenter;font.pixelSize:15}
    }
    Timer{interval:page.game==="snake"?180:32;repeat:true;running:page.visible&&!page.paused&&page.game!=="2048";onTriggered:page.tick()}
    Timer{interval:5000;repeat:true;running:page.visible;onTriggered:if(page.state.score>page.best)page.persist()}
    Keys.onLeftPressed:move("left");Keys.onRightPressed:move("right");Keys.onUpPressed:move("up");Keys.onDownPressed:move("down");Keys.onSpacePressed:{if(!state.over){paused=!paused;if(paused)persist();field.requestPaint();}}
    onVisibleChanged:if(!visible)paused=true
    Component.onCompleted:forceActiveFocus()
}
