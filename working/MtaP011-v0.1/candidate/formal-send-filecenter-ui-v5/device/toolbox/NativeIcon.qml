import QtQuick 2.10
Rectangle {
    id:icon
    property string kind:"folder"
    radius:22
    gradient:Gradient {GradientStop {position:0;color:icon.kind==="folder"?"#ffa242":icon.kind==="game"?"#8971ff":icon.kind==="video"?"#ff89b0":"#19dcb5"}GradientStop {position:1;color:icon.kind==="folder"?"#e96c19":icon.kind==="game"?"#5442bc":icon.kind==="video"?"#e3457a":"#049d80"}}
    Canvas {
        anchors.fill:parent
        onPaint:{var c=getContext("2d");c.scale(width/96,height/96);c.fillStyle="#f8ffff";c.strokeStyle="#f8ffff";c.lineWidth=5;c.lineCap="round";c.lineJoin="round";
            if(icon.kind==="folder"){c.beginPath();c.moveTo(20,32);c.lineTo(39,32);c.lineTo(46,39);c.lineTo(77,39);c.lineTo(77,70);c.quadraticCurveTo(77,75,71,75);c.lineTo(25,75);c.quadraticCurveTo(20,75,20,70);c.closePath();c.fill();}
            else if(icon.kind==="game"){c.beginPath();c.moveTo(29,31);c.lineTo(66,31);c.quadraticCurveTo(75,31,77,44);c.lineTo(81,65);c.quadraticCurveTo(82,73,73,72);c.lineTo(60,62);c.lineTo(35,62);c.lineTo(24,71);c.quadraticCurveTo(13,75,15,64);c.lineTo(19,44);c.quadraticCurveTo(20,31,29,31);c.closePath();c.stroke();c.beginPath();c.moveTo(26,47);c.lineTo(40,47);c.moveTo(33,40);c.lineTo(33,54);c.stroke();c.beginPath();c.arc(62,43,4,0,Math.PI*2);c.arc(71,53,4,0,Math.PI*2);c.fill();}
            else if(icon.kind==="video"){c.strokeRect(19,29,58,43);c.beginPath();c.moveTo(34,18);c.lineTo(43,28);c.moveTo(63,18);c.lineTo(54,28);c.stroke();c.beginPath();c.moveTo(41,39);c.lineTo(59,50);c.lineTo(41,61);c.closePath();c.fill();}
            else if(icon.kind==="transfer"){c.strokeRect(20,20,32,54);c.beginPath();c.moveTo(58,37);c.lineTo(78,37);c.lineTo(70,29);c.moveTo(78,37);c.lineTo(70,45);c.moveTo(78,58);c.lineTo(58,58);c.lineTo(66,50);c.moveTo(58,58);c.lineTo(66,66);c.stroke();}
            else{c.beginPath();c.moveTo(22,24);c.lineTo(22,73);c.lineTo(77,73);c.stroke();c.beginPath();c.moveTo(31,59);c.lineTo(43,44);c.lineTo(56,51);c.lineTo(73,29);c.stroke();}}
    }
}

