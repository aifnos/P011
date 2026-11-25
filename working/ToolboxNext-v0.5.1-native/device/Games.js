/* Pure ES5 game rules, shared by Qt Quick and Node regression tests. */
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function addTile(state, rng) {
    var empty=[],i; for(i=0;i<16;i++) if(!state.cells[i]) empty.push(i);
    if(empty.length) state.cells[empty[Math.floor(rng()*empty.length)]]=rng()<0.9?2:4;
}
function new2048(rng) { var s={cells:[],score:0,over:false,won:false};for(var i=0;i<16;i++)s.cells.push(0);addTile(s,rng);addTile(s,rng);return s; }
function slide2048(state, direction, rng) {
    var s=clone(state),before=s.cells.join(','),i,j,idx,line,out,score=0;
    for(i=0;i<4;i++) {
        idx=[];for(j=0;j<4;j++)idx.push(direction==='left'?i*4+j:direction==='right'?i*4+3-j:direction==='up'?j*4+i:(3-j)*4+i);
        line=[];for(j=0;j<4;j++)if(s.cells[idx[j]])line.push(s.cells[idx[j]]);
        out=[];for(j=0;j<line.length;j++){if(j+1<line.length&&line[j]===line[j+1]){out.push(line[j]*2);score+=line[j]*2;j++;}else out.push(line[j]);}
        while(out.length<4)out.push(0);for(j=0;j<4;j++)s.cells[idx[j]]=out[j];
    }
    s.changed=before!==s.cells.join(',');s.score+=score;if(s.changed)addTile(s,rng);
    s.over=true;s.won=false;
    for(i=0;i<16;i++){if(s.cells[i]>=2048)s.won=true;if(!s.cells[i]||(i%4<3&&s.cells[i]===s.cells[i+1])||(i<12&&s.cells[i]===s.cells[i+4]))s.over=false;}
    return s;
}
function snakeFood(s,rng) {var empty=[],i,j,hit;for(i=0;i<s.w*s.h;i++){hit=false;for(j=0;j<s.body.length;j++)if(s.body[j]===i)hit=true;if(!hit)empty.push(i);}return empty.length?empty[Math.floor(rng()*empty.length)]:-1;}
function newSnake(rng) {var s={w:24,h:8,body:[51,50,49],direction:'right',pending:'right',turned:false,score:0,over:false,won:false};s.food=snakeFood(s,rng);return s;}
function turnSnake(s,d) {var opposite={left:'right',right:'left',up:'down',down:'up'};if(!s.turned&&opposite[d]&&d!==opposite[s.direction]&&d!==s.direction){s.pending=d;s.turned=true;}return s;}
function tickSnake(state,rng) {
    var s=clone(state);if(s.over)return s;s.direction=s.pending;s.turned=false;
    var x=s.body[0]%s.w,y=Math.floor(s.body[0]/s.w);x+=s.direction==='right'?1:s.direction==='left'?-1:0;y+=s.direction==='down'?1:s.direction==='up'?-1:0;
    var next=y*s.w+x,grow=next===s.food,body=s.body.slice(0,grow?s.body.length:s.body.length-1);
    if(x<0||x>=s.w||y<0||y>=s.h||body.indexOf(next)>=0){s.over=true;return s;}
    body.unshift(next);s.body=body;if(grow){s.score+=10;s.food=snakeFood(s,rng);if(s.food<0){s.over=true;s.won=true;}}return s;
}
function newBricks() {var blocks=[];for(var i=0;i<24;i++)blocks.push(true);return {x:300,y:135,vx:110,vy:-110,paddle:300,blocks:blocks,score:0,over:false,won:false};}
function tickBricks(state,dt) {
    var s=clone(state);if(s.over)return s;dt=Math.max(0,Math.min(0.05,dt));
    var steps=Math.max(1,Math.ceil(dt/0.008)),step=dt/steps;
    for(var k=0;k<steps;k++) {
        var oldY=s.y;s.x+=s.vx*step;s.y+=s.vy*step;
        if(s.x<5){s.x=5;s.vx=Math.abs(s.vx);}if(s.x>595){s.x=595;s.vx=-Math.abs(s.vx);}if(s.y<5){s.y=5;s.vy=Math.abs(s.vy);}
        if(s.vy>0&&oldY<=160&&s.y>=160&&Math.abs(s.x-s.paddle)<=43){s.y=160;s.vy=-Math.abs(s.vy);s.vx=150*(s.x-s.paddle)/43;}
        for(var i=0;i<s.blocks.length;i++){var bx=8+(i%8)*74,by=12+Math.floor(i/8)*22;if(s.blocks[i]&&s.x>=bx-4&&s.x<=bx+72&&s.y>=by-4&&s.y<=by+20){s.blocks[i]=false;s.vy=-s.vy;s.score+=10;break;}}
        if(s.y>186){s.over=true;break;}
    }
    if(s.blocks.indexOf(true)<0){s.won=true;s.over=true;}return s;
}
if(typeof module!=='undefined')module.exports={new2048:new2048,slide2048:slide2048,newSnake:newSnake,turnSnake:turnSnake,tickSnake:tickSnake,newBricks:newBricks,tickBricks:tickBricks};
