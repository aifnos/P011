#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loopback-only, token-protected, fixed-operation bridge for one trial.
No file server, shell evaluator, CORS permission or WebChannel exposure.
"""
import os, sys, time, signal, socket, threading
import p011_json as J
import tools_metrics as M
from tools_services import Services, atomic
STOP=False

def stopping(sig,frame):
    global STOP
    STOP=True

def path_url(p):
    safe=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/'
    return 'file://'+''.join(chr(x) if x in safe else '%%%02X'%x for x in os.fsencode(p))

def catalog(root):
    result=[];audio=('.mp3','.wav','.flac','.ogg','.m4a','.aac','.opus');video=('.mp4','.mkv','.avi','.webm','.mov','.m4v')
    for base in (root+'/media','/mnt/data/p011-media'):
        if not os.path.isdir(base) or os.path.islink(base):continue
        for name in sorted(os.listdir(base))[:400]:
            path=os.path.join(base,name);real=os.path.realpath(path);ext=os.path.splitext(name)[1].lower()
            if not real.startswith(os.path.realpath(base)+'/') or os.path.islink(path) or not os.path.isfile(path) or ext not in audio+video:continue
            result.append({'name':os.fsencode(name).decode('utf-8','replace'),'url':path_url(real),'kind':'audio' if ext in audio else 'video','bytes':os.path.getsize(real),'folder':'测试包' if base.startswith(root) else '本地媒体'})
            if len(result)>=200:return result
    return result

class Bridge:
    def __init__(self,root):
        self.root=root;self.logs=root+'/logs';self.lock=threading.RLock();self.started=time.monotonic()
        self.token=os.urandom(32).hex();self.stop_sampler=False;self.requests=0
        self.cached={'battery':{'rows':[],'history':[]},'radio':{'wifi':[],'cell':[],'bluetooth':[],'errors':[],'interfaces':[]},'capabilities':{},'media':catalog(root)}
        self.service=Services(root,self.event)
        self.s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.s.bind(('127.0.0.1',0));self.port=self.s.getsockname()[1]
        self.host='127.0.0.1:'+str(self.port);self.s.listen(4);self.s.settimeout(.2)
        self.thread=threading.Thread(target=self.sampler);self.thread.daemon=True
    def event(self,message):
        line={'epoch':time.time(),'monotonic':time.monotonic(),'event':str(message)[:600]}
        with open(self.logs+'/tools-events.jsonl','a',encoding='utf-8') as f:f.write(J.dumps(line)+'\n')
    def snapshot(self):
        with self.lock:d=dict(self.cached)
        d.update(self.service.state());d.update({'schema':'p011.tools.v0.4','epoch':time.time(),'uptime_seconds':int(time.monotonic()-self.started)})
        return d
    def sampler(self):
        last_radio=-99;caps=False;history=[]
        while not self.stop_sampler and not STOP:
            try:
                b=M.battery();history.append({k:b.get(k) for k in ('epoch','monotonic','capacity','voltage','current','temperature','power')});history=history[-120:];b['history']=list(history)
                with self.lock:self.cached['battery']=b
                with open(self.logs+'/battery-samples.jsonl','a',encoding='utf-8') as f:f.write(J.dumps(history[-1])+'\n')
                if time.monotonic()-last_radio>12:
                    r=M.radio()
                    with self.lock:self.cached['radio']=r
                    atomic(self.logs+'/radio-latest.json',J.dumps(r,indent=2).encode('utf-8'));last_radio=time.monotonic()
                if not caps:
                    c=M.capabilities()
                    with self.lock:self.cached['capabilities']=c
                    atomic(self.logs+'/capabilities.json',J.dumps(c,indent=2).encode('utf-8'));caps=True
            except Exception as e:self.event('sampler_error:'+type(e).__name__+':'+str(e))
            for _ in range(10):
                if self.stop_sampler or STOP:break
                time.sleep(.2)
    def response(self,code,data):
        payload=J.dumps(data).encode('utf-8')
        return ('HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n'%(code,'OK' if code==200 else 'Error',len(payload))).encode('ascii')+payload
    def parse(self,c):
        c.settimeout(1.5);data=b'';start=time.monotonic()
        while b'\r\n\r\n' not in data:
            if len(data)>8192 or time.monotonic()-start>3:raise ValueError('header limit')
            p=c.recv(2048)
            if not p:raise ValueError('truncated header')
            data+=p
        head,body=data.split(b'\r\n\r\n',1);lines=head.decode('ascii','strict').split('\r\n');method,path,ver=lines[0].split(' ')
        if ver not in ('HTTP/1.0','HTTP/1.1') or path not in ('/api/state','/api/media','/api/action'):raise ValueError('path')
        headers={}
        for line in lines[1:]:
            k,sep,v=line.partition(':');k=k.strip().lower()
            if not sep or k in headers:raise ValueError('duplicate/invalid header')
            headers[k]=v.strip()
        supplied=headers.get('x-p011-token','')
        if len(supplied)!=len(self.token) or sum(ord(a)^ord(b) for a,b in zip(supplied,self.token)):raise PermissionError('token')
        if headers.get('host')!=self.host or 'transfer-encoding' in headers:raise PermissionError('host or transfer encoding')
        if headers.get('origin','') not in ('','null','file://'):raise PermissionError('origin')
        size=int(headers.get('content-length','0'))
        if size<0 or size>64 or len(body)>size:raise ValueError('body limit')
        while len(body)<size:
            p=c.recv(size-len(body))
            if not p:raise ValueError('truncated body')
            body+=p
        return method,path,body.decode('ascii','strict')
    def action(self,name):
        if name=='adb_on':return self.service.adb_set(1)
        if name=='adb_off':return self.service.adb_set(0)
        if name=='adb_restore':
            from tools_services import restore_adb
            message=restore_adb(self.root);self.event('adb_restore_user');return {'message':message}
        if name=='ssh_usb':return self.service.start_ssh('usb')
        if name=='ssh_wifi':return self.service.start_ssh('wifi')
        if name=='ssh_stop':return self.service.stop_ssh()
        if name=='media_refresh':
            with self.lock:self.cached['media']=catalog(self.root)
            return {'message':'媒体列表已刷新'}
        raise ValueError('操作不在白名单内')
    def run(self):
        config='.pragma library\nvar endpoint = '+J.dumps('http://'+self.host)+';\nvar token = '+J.dumps(self.token)+';\n'
        atomic(self.root+'/pages/Session.js',config.encode('utf-8'));self.thread.start();atomic(self.logs+'/tools.ready',b'READY\n')
        self.event('bridge_started_loopback_token_required');last_save=0
        try:
            while not STOP and time.monotonic()-self.started<1200:
                if os.path.isfile(self.logs+'/stop.request'):break
                self.service.tick()
                if time.monotonic()-last_save>10:
                    atomic(self.logs+'/tools-snapshot.json',J.dumps(self.snapshot(),indent=2).encode('utf-8'));last_save=time.monotonic()
                try:c,peer=self.s.accept()
                except socket.timeout:continue
                try:
                    self.requests+=1
                    if self.requests>8000:raise RuntimeError('request ceiling')
                    method,path,body=self.parse(c)
                    if method=='GET' and path=='/api/state':payload=self.snapshot()
                    elif method=='GET' and path=='/api/media':payload={'media':self.cached['media']}
                    elif method=='POST' and path=='/api/action':payload=self.action(body)
                    else:raise ValueError('method')
                    c.sendall(self.response(200,{'ok':True,'data':payload}))
                except PermissionError:
                    try:c.sendall(self.response(403,{'ok':False,'error':'Denied'}))
                    except OSError:pass
                except Exception as e:
                    try:c.sendall(self.response(400,{'ok':False,'error':str(e)[:500]}))
                    except OSError:pass
                    self.event('request_error:'+type(e).__name__+':'+str(e)[:350])
                finally:c.close()
        finally:
            self.stop_sampler=True;errors=self.service.close();self.thread.join(timeout=1);self.s.close()
            atomic(self.logs+'/tools-finished.json',J.dumps({'errors':errors,'requests':self.requests,'config_restore_and_ssh_cleanup_ok':not errors},indent=2).encode('utf-8'))
            self.event('bridge_finished')
            if errors:raise RuntimeError('; '.join(errors))

if __name__=='__main__':
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stopping)
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    try:Bridge(os.path.realpath(os.path.dirname(__file__))).run()
    except Exception as e:print(type(e).__name__+': '+str(e),file=sys.stderr);sys.exit(1)
