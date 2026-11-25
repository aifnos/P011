import QtQuick 2.10
import "Games.js" as Rules
import "Theme.js" as Theme
Item {
    id:page;objectName:"gamesPage";property var app
    property string game:"snake"
    property var state:Rules.newSnake(Math.random)
    property bool paused:true
    property int best:app&&app.telemetry.scores?Number(app.telemetry.scores[game]||0):0
    property string headerTitle:"小游戏中心"
    property string headerAction:paused?"开始":"暂停"
    property bool actionEnabled:!state.over
    function primaryAction(){if(state.over)return;paused=!paused;if(paused)persist();forceActiveFocus();field.requestPaint();}
    function persist(){if(app)app.saveScore(game,Number(state.score||0));}
    function start(name){persist();game=name;paused=true;state=game==="snake"?Rules.newSnake(Math.random):game==="2048"?Rules.new2048(Math.random):Rules.newBricks();field.requestPaint();forceActiveFocus();}
    function prepareLeave(){paused=true;persist();}
    function move(direction){if(paused||state.over)return;if(game==="snake")state=Rules.turnSnake(state,direction);else if(game==="2048"){state=Rules.slide2048(state,direction,Math.random);if(state.over)persist();}else if(direction==="left"||direction==="right")state.paddle=Math.max(40,Math.min(560,state.paddle+(direction==="left"?-35:35)));field.requestPaint();}
    function tick(){if(paused||state.over)return;if(game==="bricks"){var shift=(brickRight.pressed?12:0)-(brickLeft.pressed?12:0);state.paddle=Math.max(40,Math.min(560,state.paddle+shift));}state=game==="snake"?Rules.tickSnake(state,Math.random):Rules.tickBricks(state,0.032);if(state.over){paused=true;persist();}field.requestPaint();}
    Row {x:12;y:4;spacing:8
        Button {objectName:"gameBackButton";text:"返回";width:72;height:54;fontSize:24;onClicked:app.open("")}
        Button {objectName:"snakeButton";text:"贪吃蛇";width:108;height:54;accent:page.game==="snake";fontSize:24;onClicked:page.start("snake")}
        Button {objectName:"mergeButton";text:"2048";width:92;height:54;accent:page.game==="2048";fontSize:24;onClicked:page.start("2048")}
        Button {objectName:"bricksButton";text:"打砖块";width:108;height:54;accent:page.game==="bricks";fontSize:24;onClicked:page.start("bricks")}
        Label {width:152;height:54;text:"得分 "+page.state.score+"\n最高 "+Math.max(page.best,page.state.score);font.pixelSize:21;color:Theme.secondary;horizontalAlignment:Text.AlignHCenter}
        Button {objectName:"gamePauseButton";text:page.headerAction;enabled:page.actionEnabled;width:108;height:54;fontSize:24;onClicked:page.primaryAction()}
        Button {text:"重来";width:88;height:54;fontSize:24;onClicked:page.start(page.game)}
    }
    Canvas {
        id:field;objectName:"gameCanvas";x:160;y:66;width:480;height:parent.height-76
        onPaint:{
            var c=getContext("2d"),s=page.state,w=width,h=height;c.reset();c.fillStyle="#191919";c.fillRect(0,0,w,h);
            if(page.game==="snake"){
                var size=Math.min(w/s.w,h/s.h),ox=(w-size*s.w)/2,oy=(h-size*s.h)/2;
                c.fillStyle="#242424";c.fillRect(ox,oy,size*s.w,size*s.h);
                c.fillStyle="#ff7256";c.fillRect(ox+(s.food%s.w)*size+2,oy+Math.floor(s.food/s.w)*size+2,size-4,size-4);
                for(var i=0;i<s.body.length;i++){c.fillStyle=i===0?"#d8fff0":"#12cfa7";c.fillRect(ox+(s.body[i]%s.w)*size+1,oy+Math.floor(s.body[i]/s.w)*size+1,size-2,size-2);}
            }else if(page.game==="2048"){
                var cell=h/4,ox2=(w-cell*4)/2;
                for(var j=0;j<16;j++){var n=s.cells[j];c.fillStyle=n?"hsl("+(160-Math.log(n)/Math.LN2*9)+",48%,"+(25+Math.min(32,Math.log(n)/Math.LN2*3))+"%)":"#3c3d42";c.fillRect(ox2+(j%4)*cell+1,Math.floor(j/4)*cell+1,cell-2,cell-2);if(n){c.fillStyle="#fff";c.font="bold "+(n>999?20:26)+"px sans-serif";c.textAlign="center";c.textBaseline="middle";c.fillText(String(n),ox2+(j%4+.5)*cell,(Math.floor(j/4)+.5)*cell);}}
            }else{
                c.save();c.scale(w/600,h/190);
                for(var b=0;b<24;b++)if(s.blocks[b]){c.fillStyle=["#12cfa7","#00b9f5","#ff7256"][Math.floor(b/8)];c.fillRect(8+b%8*74,12+Math.floor(b/8)*22,68,16);}
                c.fillStyle="#fff";c.beginPath();c.arc(s.x,s.y,5,0,Math.PI*2);c.fill();c.fillStyle="#12cfa7";c.fillRect(s.paddle-40,166,80,7);c.restore();
            }
            if(page.paused||s.over){c.fillStyle="#cc0f0f0f";c.fillRect(0,h/2-25,w,50);c.fillStyle="#fff";c.font="24px sans-serif";c.textAlign="center";c.textBaseline="middle";c.fillText(s.over?(s.won?"完成！点击重来":"本局结束 · 点击重来"):"已暂停 · 点右上角开始",w/2,h/2);}
        }
        MouseArea {
            anchors.fill:parent;property real startX:0;property real startY:0
            onPressed:{startX=mouse.x;startY=mouse.y;if(page.game==="bricks"&&!page.paused){page.state.paddle=Math.max(40,Math.min(560,mouse.x/width*600));field.requestPaint();}}
            onPositionChanged:if(pressed&&page.game==="bricks"&&!page.paused){page.state.paddle=Math.max(40,Math.min(560,mouse.x/width*600));field.requestPaint();}
            onReleased:{var dx=mouse.x-startX,dy=mouse.y-startY;if(Math.max(Math.abs(dx),Math.abs(dy))>18)page.move(Math.abs(dx)>Math.abs(dy)?(dx>0?"right":"left"):(dy>0?"down":"up"));}
        }
    }
    Item {x:12;y:66;width:136;height:parent.height-76
        Button {objectName:"gameUpButton";width:136;height:(parent.height-8)/2;text:"↑ 上";fontSize:32;visible:page.game!=="bricks";onClicked:page.move("up")}
        Button {objectName:"gameDownButton";y:(parent.height+8)/2;width:136;height:(parent.height-8)/2;text:"↓ 下";fontSize:32;visible:page.game!=="bricks";onClicked:page.move("down")}
        Button {id:brickLeft;objectName:"brickLeftButton";width:136;height:parent.height;text:"←";fontSize:48;visible:page.game==="bricks";onPressedChanged:if(pressed)page.move("left")}
    }
    Item {x:652;y:66;width:136;height:parent.height-76
        Button {objectName:"gameLeftButton";width:136;height:(parent.height-8)/2;text:"← 左";fontSize:32;visible:page.game!=="bricks";onClicked:page.move("left")}
        Button {objectName:"gameRightButton";y:(parent.height+8)/2;width:136;height:(parent.height-8)/2;text:"右 →";fontSize:32;visible:page.game!=="bricks";onClicked:page.move("right")}
        Button {id:brickRight;objectName:"brickRightButton";width:136;height:parent.height;text:"→";fontSize:48;visible:page.game==="bricks";onPressedChanged:if(pressed)page.move("right")}
    }
    Timer {interval:page.game==="snake"?180:32;repeat:true;running:page.visible&&!page.paused&&page.game!=="2048";onTriggered:page.tick()}
    Timer {interval:5000;repeat:true;running:page.visible;onTriggered:if(page.state.score>page.best)page.persist()}
    Keys.onLeftPressed:move("left");Keys.onRightPressed:move("right");Keys.onUpPressed:move("up");Keys.onDownPressed:move("down");Keys.onSpacePressed:primaryAction()
    onVisibleChanged:if(!visible)paused=true
    Component.onCompleted:forceActiveFocus()
}
