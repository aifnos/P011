import QtQuick 2.10
import QtWebEngine 1.4
import "qrc:/ZybQmlFiles/Style"
Item{
 id:page;property var app:null;property bool internetEnabled:false;property bool showBookmarks:false
 property string localHome:Qt.resolvedUrl("browser/home.html").toString();property string errorText:""
 function prepareLeave(){web.stop();if(app)app.expanded=false;}
 function valid(u){
  if(u===localHome||u==="about:blank")return true;
  if(!/^https?:\/\//i.test(u))return false;
  var a=u.split("/")[2].toLowerCase();if(a.indexOf("@")>=0)return false;
  var h=a.split(":")[0];if(h==="localhost"||h==="0.0.0.0"||h.indexOf("127.")===0||a.charAt(0)==="[")return false;
  return h.length>0;
 }
 function visit(input){
  var u=input.trim();if(!u)return;
  if(u.indexOf(" ")>=0)u="https://www.bing.com/search?q="+encodeURIComponent(u);
  else if(!/^[a-z][a-z0-9+.-]*:/i.test(u))u="https://"+u;
  if(!valid(u)){if(app)app.toast("仅允许 HTTP/HTTPS 和本工具主页；不访问调试服务地址。");return;}
  var load=function(){page.errorText="";web.url=u;page.showBookmarks=false;if(app)app.mark("browser_navigate");};
  if(u!==localHome&&u!=="about:blank"&&!internetEnabled){
   app.confirm("本机使用旧版 WebEngine，未验证网页沙箱安全性。\n仅浏览可信网页，不登录重要账号；不会忽略证书错误。联网后暂停自动网页截屏，手动截屏仍可用。",function(){page.internetEnabled=true;load();},2);
  }else load();
 }
 Rectangle{id:bar;x:8;y:2;width:parent.width-16;height:40;color:Style.mainbgColor
  Row{spacing:5
   ToolButton{text:"‹";width:43;height:38;enabled:web.canGoBack;onClicked:web.goBack()}
   ToolButton{text:"›";width:43;height:38;enabled:web.canGoForward;onClicked:web.goForward()}
   ToolButton{text:web.loading?"停止":"刷新";width:70;height:38;onClicked:web.loading?web.stop():web.reload()}
   ToolButton{text:"主页";width:70;height:38;onClicked:web.url=page.localHome}
   Rectangle{width:Math.max(180,page.width-544);height:38;radius:5;color:"#292b30"
    ToolText{anchors.fill:parent;anchors.margins:6;text:web.url.toString()===page.localHome?"本地主页 · 点此输入网址":web.url.toString();font.pixelSize:17}
    MouseArea{anchors.fill:parent;onClicked:if(app)app.editUrl(web.url.toString()===page.localHome?"":web.url.toString(),function(v){page.visit(v);})}
   }
   ToolButton{text:"−";width:39;height:38;onClicked:web.zoomFactor=Math.max(.5,web.zoomFactor-.1)}
   ToolButton{text:"＋";width:39;height:38;onClicked:web.zoomFactor=Math.min(2,web.zoomFactor+.1)}
   ToolButton{text:"书签";width:70;height:38;onClicked:page.showBookmarks=!page.showBookmarks}
   ToolButton{text:app&&app.expanded?"还原":"展开";width:72;height:38;onClicked:if(app)app.expanded=!app.expanded}
  }
 }
 WebEngineProfile{id:privateProfile;offTheRecord:true;onDownloadRequested:{download.cancel();if(app)app.toast("测试版暂不下载网页文件");}}
 WebEngineView{
  id:web;anchors.left:parent.left;anchors.right:parent.right;anchors.top:bar.bottom;anchors.topMargin:4;anchors.bottom:parent.bottom
  profile:privateProfile;url:page.localHome;zoomFactor:1.0;webChannel:null;backgroundColor:"#0f0f0f"
  settings.localContentCanAccessFileUrls:false
  settings.localContentCanAccessRemoteUrls:false
  settings.javascriptCanOpenWindows:false
  settings.javascriptCanAccessClipboard:false
  settings.pluginsEnabled:false
  onNavigationRequested:{
   var u=request.url.toString();
   if(!page.valid(u)||(!page.internetEnabled&&u!==page.localHome&&u!=="about:blank")){request.action=WebEngineView.IgnoreRequest;if(app)app.toast("请先从地址栏确认联网浏览");}
  }
  onCertificateError:{error.rejectCertificate();page.errorText="证书验证失败：先检查设备日期和时间，不会忽略证书错误。";if(app)app.mark("browser_certificate_rejected");}
  onFeaturePermissionRequested:grantFeaturePermission(securityOrigin,feature,false)
  onNewViewRequested:if(app)app.mark("browser_popup_ignored")
  onLoadingChanged:{
   if(loadRequest.status===WebEngineView.LoadSucceededStatus){page.errorText="";if(app)app.noteAction("browser_loaded");}
   if(loadRequest.status===WebEngineView.LoadFailedStatus){page.errorText=loadRequest.errorString;if(app)app.mark("browser_load_failed");}
  }
  onRenderProcessTerminated:{page.errorText="网页进程已退出，可返回工具箱；错误已记录。";if(app)app.mark("browser_renderer_terminated");}
 }
 Rectangle{x:0;y:43;width:parent.width*web.loadProgress/100;height:2;color:Style.mainColor;visible:web.loading;z:4}
 Rectangle{anchors.left:parent.left;anchors.right:parent.right;anchors.bottom:parent.bottom;height:53;color:"#ee3c3d42";visible:page.errorText!=="";z:5
  ToolText{anchors.fill:parent;anchors.margins:6;text:page.errorText;wrapMode:Text.Wrap;elide:Text.ElideNone;font.pixelSize:18}
  MouseArea{anchors.fill:parent;onClicked:page.errorText=""}
 }
 Rectangle{anchors.fill:web;z:10;color:Style.mainbgColor;visible:page.showBookmarks
  ToolButton{x:12;y:4;width:260;height:38;text:"收藏当前页（本次会话）";onClicked:if(app&&app.bookmarks.length<20){app.bookmarks=app.bookmarks.concat([{title:web.title||web.url.toString(),url:web.url.toString()}]);app.toast("已加入本次会话书签");}}
  ListView{x:12;y:48;width:parent.width-24;height:parent.height-50;clip:true;model:app?app.bookmarks:[];spacing:4
   delegate:ToolButton{width:parent?parent.width:760;height:44;text:modelData.title;onClicked:page.visit(modelData.url)}
  }
 }
 Component.onDestruction:web.stop()
}
