const assert=require('assert');const g=require('../device/Games.js');let count=0;
function test(name,fn){fn();count++;console.log('PASS '+name);}
test('2048 new board has two tiles',()=>{const s=g.new2048(()=>0);assert.equal(s.cells.filter(Boolean).length,2);});
test('2048 merges each tile once',()=>{let s={cells:[2,2,2,2,0,0,0,0,0,0,0,0,0,0,0,0],score:0};let next=g.slide2048(s,'left',()=>0);assert.deepEqual(next.cells.slice(0,2),[4,4]);assert.equal(next.score,8);assert.equal(s.cells[0],2);});
test('2048 vertical merge',()=>{let s={cells:[2,0,0,0,2,0,0,0,4,0,0,0,4,0,0,0],score:0};let n=g.slide2048(s,'up',()=>0);assert.equal(n.cells[0],4);assert.equal(n.cells[4],8);assert.equal(n.score,12);});
test('2048 no-op does not spawn',()=>{let s={cells:[2,4,8,16,0,0,0,0,0,0,0,0,0,0,0,0],score:0};assert.deepEqual(g.slide2048(s,'left',()=>0).cells,s.cells);});
test('2048 detects game over',()=>{let s={cells:[2,4,2,4,4,2,4,2,2,4,2,4,4,2,4,2],score:0};assert(g.slide2048(s,'left',()=>0).over);});
test('snake cannot reverse or double-turn in a tick',()=>{let s=g.newSnake(()=>0);g.turnSnake(s,'left');assert.equal(s.pending,'right');g.turnSnake(s,'up');g.turnSnake(s,'left');assert.equal(s.pending,'up');});
test('snake moves and collides with wall',()=>{let s=g.newSnake(()=>0);s.body=[23,22,21];assert(g.tickSnake(s,()=>0).over);s=g.newSnake(()=>0);assert.equal(g.tickSnake(s,()=>0).body[0],52);});
test('snake eats and grows',()=>{let s=g.newSnake(()=>0);s.food=52;let n=g.tickSnake(s,()=>0);assert.equal(n.score,10);assert.equal(n.body.length,4);assert(!n.body.includes(n.food));});
test('snake moving into vacating tail is valid',()=>{let s={w:4,h:4,body:[5,6,10,9],direction:'down',pending:'down',turned:false,score:0,over:false,food:0};assert(!g.tickSnake(s,()=>0).over);});
test('bricks walls and paddle bounce',()=>{let s=g.newBricks();s.x=594;s.y=120;s.vx=300;assert(g.tickBricks(s,.05).vx<0);s=g.newBricks();s.y=159;s.vy=120;assert(g.tickBricks(s,.032).vy<0);});
test('bricks miss loses and dead game stays still',()=>{let s=g.newBricks();s.y=185;s.x=5;s.vy=120;let n=g.tickBricks(s,.05);assert(n.over);assert.deepEqual(g.tickBricks(n,.05),n);});
test('bricks clear earns score',()=>{let s=g.newBricks();s.x=30;s.y=10;s.vy=110;assert(g.tickBricks(s,.05).score>0);});
console.log('GAME_RULES_PASS '+count);
