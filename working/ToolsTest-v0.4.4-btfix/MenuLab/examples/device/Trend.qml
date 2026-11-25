import QtQuick 2.10
Canvas{
 id:plot;property var points:[];property string metric:"voltage"
 onPointsChanged:requestPaint();onMetricChanged:requestPaint();onWidthChanged:requestPaint();onHeightChanged:requestPaint()
 onPaint:{
  var c=getContext("2d");c.clearRect(0,0,width,height);c.fillStyle="#222427";c.fillRect(0,0,width,height);
  var vs=[];for(var i=0;i<points.length;i++){var v=points[i][metric];if(v!==null&&v!==undefined&&isFinite(v))vs.push(v);}
  c.strokeStyle="#42454b";c.lineWidth=1;for(var g=1;g<4;g++){c.beginPath();c.moveTo(0,g*height/4);c.lineTo(width,g*height/4);c.stroke();}
  if(vs.length<2)return;var lo=Math.min.apply(null,vs),hi=Math.max.apply(null,vs);if(hi-lo<0.02){lo-=0.01;hi+=0.01;}
  c.strokeStyle="#12CFA7";c.lineWidth=2;c.beginPath();var first=true;
  for(var j=0;j<points.length;j++){var n=points[j][metric];if(n===null||n===undefined||!isFinite(n)){first=true;continue;}
   var x=5+j*(width-10)/Math.max(1,points.length-1),y=height-8-(n-lo)*(height-16)/(hi-lo);if(first)c.moveTo(x,y);else c.lineTo(x,y);first=false;
  }c.stroke();
 }
}
