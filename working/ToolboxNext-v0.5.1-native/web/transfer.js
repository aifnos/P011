/* No third-party scripts, credentials in URLs, persistent browser storage or HTML injection. */
(function () {
  'use strict';
  var code='', directory='', offset=0, next=null, busy=false;
  var el=function(id){return document.getElementById(id);};
  function status(message){el('status').textContent=message;}
  function lock(value){busy=value;el('upload').disabled=value||!directory;el('refresh').disabled=value;el('up').disabled=value||!directory;el('more').disabled=value;el('logout').disabled=value;el('files').disabled=value;}
  function request(path, options){options=options||{};options.headers=Object.assign({},options.headers,{'X-P011-Code':code});return fetch(path,options).then(function(r){if(r.status===403)throw Error('访问码错误、已过期或尝试过多。请检查笔上的传输状态。');if(!r.ok)return r.json().then(function(o){throw Error(o.error||'操作失败');});return r;});}
  function list(){lock(true);return request('/api/files?path='+encodeURIComponent(directory)+'&offset='+offset).then(function(r){return r.json();}).then(function(o){
    var result=o.data;next=result.next;el('listing').replaceChildren();el('path').textContent=directory||'用户目录';el('more').hidden=next===null;
    result.entries.forEach(function(item){var row=document.createElement('li'),name=document.createElement('span'),meta=document.createElement('span'),button=document.createElement('button');name.className='file-name';name.textContent=item.name;meta.className='file-meta';meta.textContent=item.kind==='directory'?'文件夹':item.kind+' · '+(item.bytes/1024).toFixed(1)+' KiB';name.appendChild(meta);button.textContent=item.kind==='directory'?'打开':'下载';button.addEventListener('click',function(){if(busy)return;if(item.kind==='directory'){directory=item.path;offset=0;list().catch(showError);}else download(item);});row.append(name,button);el('listing').appendChild(row);});
    if(!result.entries.length){var empty=document.createElement('li');empty.textContent='这里还没有文件';el('listing').appendChild(empty);}
    el('login').hidden=true;el('workspace').hidden=false;status(result.limited?'当前目录过大，只枚举前 2000 项。':'已连接。文件留在你的学习笔上，不经过云端。');
  }).finally(function(){lock(false);});}
  function showError(e){status(e.message||String(e));lock(false);}
  function download(item){lock(true);request('/api/download?path='+encodeURIComponent(item.path)).then(function(r){return r.blob();}).then(function(blob){var url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=item.name;a.click();setTimeout(function(){URL.revokeObjectURL(url);},10000);status('已请求下载：'+item.name);}).catch(showError).finally(function(){lock(false);});}
  function upload(file){return new Promise(function(resolve,reject){var x=new XMLHttpRequest();x.open('POST','/api/upload?path='+encodeURIComponent(directory+'/'+file.name));x.setRequestHeader('X-P011-Code',code);x.setRequestHeader('Content-Type','application/octet-stream');x.timeout=180000;x.upload.onprogress=function(e){if(e.lengthComputable)el('progress').value=100*e.loaded/e.total;};x.onload=function(){try{var o=JSON.parse(x.responseText);if(x.status!==200||!o.ok)throw Error(o.error||'上传失败');resolve();}catch(e){reject(e);}};x.onerror=function(){reject(Error('网络中断，文件没有完成导入'));};x.ontimeout=function(){reject(Error('上传超时，请检查笔上服务是否仍开启'));};x.send(file);});}
  el('login-form').addEventListener('submit',function(e){e.preventDefault();code=el('code').value;if(!/^\d{8}$/.test(code)){status('请输入 8 位访问码');return;}directory='';offset=0;list().then(function(){el('code').value='';}).catch(showError);});
  el('up').onclick=function(){if(busy)return;directory=directory.split('/').slice(0,-1).join('/');offset=0;list().catch(showError);};
  el('refresh').onclick=function(){list().catch(showError);};el('more').onclick=function(){offset=next||0;list().catch(showError);};
  el('logout').onclick=function(){code='';el('workspace').hidden=true;el('login').hidden=false;el('listing').replaceChildren();el('files').value='';status('已退出浏览器；笔上的服务仍按自身倒计时关闭。');};
  el('upload').onclick=async function(){if(busy||!directory)return;var files=Array.from(el('files').files);if(!files.length){status('请先选择文件');return;}lock(true);el('progress').hidden=false;var completed=0;try{for(var i=0;i<files.length;i++){if(files[i].size>64*1024*1024||files[i].size===0)throw Error('单文件必须大于 0 且不超过 64 MiB');status('正在上传 '+(i+1)+'/'+files.length+'：'+files[i].name);await upload(files[i]);completed++;}await list();el('files').value='';status('已导入 '+completed+' 个文件。');}catch(e){status('已完成 '+completed+' 个；'+e.message);}finally{el('progress').hidden=true;lock(false);}};
}());
