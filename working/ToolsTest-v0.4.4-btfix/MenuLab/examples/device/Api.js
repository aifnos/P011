.pragma library
.import "Session.js" as Session
function request(path, action, done) {
    var x=new XMLHttpRequest(), finished=false;
    function finish(ok,data){if(finished)return;finished=true;try{done(ok,data);}catch(e){console.warn("P011_TOOLS_CALLBACK",String(e));}}
    x.onreadystatechange=function(){
        if(x.readyState!==XMLHttpRequest.DONE)return;
        try{var o=JSON.parse(x.responseText);finish(x.status===200&&o.ok,o.ok?o.data:{error:o.error});}
        catch(e){finish(false,{error:"本地服务未就绪（HTTP "+x.status+"）"});}
    };
    try{x.open(action?"POST":"GET",Session.endpoint+path);x.setRequestHeader("X-P011-Token",Session.token);if(action)x.setRequestHeader("Content-Type","text/plain");x.send(action||"");}
    catch(e){finish(false,{error:"本地服务连接失败"});}
    return x;
}
