#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loopback-only, token-protected, fixed-operation bridge for one trial.
No file server, shell evaluator, CORS permission or WebChannel exposure.
"""
import os, sys, time, signal, socket, threading, subprocess, re, select
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

def catalog(root, paths=None):
    result=[];audio=('.mp3','.wav','.flac','.ogg','.m4a','.aac','.opus');video=('.mp4','.mkv','.avi','.webm','.mov','.m4v')
    for base in (root+'/media','/mnt/data/p011-media'):
        if not os.path.isdir(base) or os.path.islink(base):continue
        for name in sorted(os.listdir(base))[:400]:
            path=os.path.join(base,name);real=os.path.realpath(path);ext=os.path.splitext(name)[1].lower()
            if not real.startswith(os.path.realpath(base)+'/') or os.path.islink(path) or not os.path.isfile(path) or ext not in audio+video:continue
            result.append({'id':len(result),'name':os.fsencode(name).decode('utf-8','replace'),'url':path_url(real),'kind':'audio' if ext in audio else 'video','bytes':os.path.getsize(real),'folder':'测试包' if base.startswith(root) else '本地媒体'})
            if paths is not None: paths.append(real)
            if len(result)>=200:return result
    return result

def duration_ms(output):
    match=re.search(r'Duration:\s*(\d+):(\d+):(\d+)\.(\d+)',output)
    if not match:return 0
    hours,minutes,seconds=[int(x) for x in match.groups()[:3]]
    nanos=int((match.group(4)+'000000000')[:9])
    return ((hours*60+minutes)*60+seconds)*1000+nanos//1000000

def parse_gst_play_frame(frame):
    """Parse one gst-play query frame, without inventing an elapsed clock."""
    if isinstance(frame,bytes):frame=frame.decode('utf-8','replace')
    frame=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',frame)
    match=re.search(r'(?<!\d)(\d+):(\d{2}):(\d{2})(?:\.(\d+))?\s*/\s*(\d+):(\d{2}):(\d{2})(?:\.(\d+))?',frame)
    if not match:return None
    values=match.groups();result=[]
    for offset in (0,4):
        hours,minutes,seconds=[int(x) for x in values[offset:offset+3]]
        if minutes>59 or seconds>59:return None
        fraction=int(((values[offset+3] or '')+'000')[:3])
        result.append(((hours*60+minutes)*60+seconds)*1000+fraction)
    return {'position_ms':result[0],'duration_ms':result[1]}

class Bridge:
    def __init__(self,root):
        self.root=root;self.logs=root+'/logs';self.lock=threading.RLock();self.started=time.monotonic()
        self.token=os.urandom(32).hex();self.stop_sampler=False;self.requests=0;self.audio=None;self.audio_reader=None;self.audio_reader_stop=None;self.audio_generation=0;self.media_paths=[]
        self.audio_state=self.new_audio_state(0,'stopped')
        self.cached={'battery':{'rows':[],'history':[]},'radio':{'wifi':[],'cell':[],'bluetooth':[],'errors':[],'interfaces':[]},'capabilities':{},'media':catalog(root,self.media_paths)}
        self.service=Services(root,self.event)
        self.s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.s.bind(('127.0.0.1',0));self.port=self.s.getsockname()[1]
        self.host='127.0.0.1:'+str(self.port);self.s.listen(4);self.s.settimeout(.2)
        self.thread=threading.Thread(target=self.sampler);self.thread.daemon=True
    def event(self,message):
        line={'epoch':time.time(),'monotonic':time.monotonic(),'event':str(message)[:600]}
        with open(self.logs+'/tools-events.jsonl','a',encoding='utf-8') as f:f.write(J.dumps(line)+'\n')
    def snapshot(self):
        with self.lock:d=dict(self.cached)
        d.update(self.service.state())
        sample_monotonic=time.monotonic()
        d.update({'schema':'p011.tools.v0.4.4','epoch':time.time(),'uptime_seconds':int(sample_monotonic-self.started),'audio_backend':self.audio_snapshot()})
        return d
    @staticmethod
    def new_audio_state(generation,status):
        return {'generation':generation,'status':status,'playing':False,'process_alive':False,'position_ms':0,'duration_ms':0,'position_sample_epoch_ms':0,'position_sample_monotonic_ms':0,'position_source':'gst_play_query','position_samples':0,'exit_code':None,'error':''}
    def audio_snapshot(self):
        with self.lock:
            proc=self.audio;reader=self.audio_reader
            draining=proc is not None and proc.poll() is not None and self.audio_state['status'] in ('starting','playing')
        if draining and reader is not None and reader is not threading.current_thread():reader.join(timeout=.5)
        with self.lock:
            state=dict(self.audio_state)
            state['process_alive']=self.audio is not None and self.audio.poll() is None
            if not state['process_alive'] and state['status'] in ('starting','playing'):
                state.update({'status':'error','error':'音频进程已退出，结束信息未完成读取','exit_code':self.audio.poll() if self.audio is not None else None})
            state['playing']=state['status']=='playing' and state['process_alive']
        return state
    def read_audio(self,proc,generation,stop_reader,stdout_log,stderr_log):
        streams={proc.stdout.fileno():(proc.stdout,stdout_log),proc.stderr.fileno():(proc.stderr,stderr_log)}
        buffers={fd:b'' for fd in streams};stdout_fd=proc.stdout.fileno();eos=False;backend_error=False;samples=0;reader_error=''
        def frame_received(fd,frame):
            nonlocal eos,backend_error,samples
            clean=re.sub(br'\x1b\[[0-?]*[ -/]*[@-~]',b'',frame).strip()
            if clean.startswith((b'ERROR ',b'ERROR:',b'Error ',b'Error:')):backend_error=True
            if fd!=stdout_fd:return
            if b'Reached end of play list.' in clean:eos=True
            sample=parse_gst_play_frame(clean)
            if sample is None:return
            epoch_ms=int(time.time()*1000);monotonic_ms=int(time.monotonic()*1000);samples+=1
            with self.lock:
                if self.audio is not proc or self.audio_generation!=generation or stop_reader.is_set():return
                self.audio_state.update(sample)
                self.audio_state.update({'status':'playing','playing':True,'process_alive':True,'position_sample_epoch_ms':epoch_ms,'position_sample_monotonic_ms':monotonic_ms,'position_samples':samples})
        try:
            while streams and not stop_reader.is_set():
                ready,_,_=select.select(list(streams),[],[],.2)
                for fd in ready:
                    block=os.read(fd,4096)
                    if not block:
                        if buffers[fd]:frame_received(fd,buffers[fd])
                        del streams[fd];del buffers[fd];continue
                    streams[fd][1].write(block)
                    frames=re.split(br'[\r\n]',buffers[fd]+block)
                    buffers[fd]=frames.pop()[-8192:]
                    for frame in frames:frame_received(fd,frame)
            if not stop_reader.is_set():
                try:code=proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    code=None;reader_error='音频后端关闭输出后未退出'
                if reader_error:error=reader_error
                elif backend_error:error='音频后端报告错误（见独立 stdout/stderr 日志）'
                elif code!=0:error='音频后端异常退出：'+str(code)
                elif not eos:error='音频后端退出但未报告正常播放结束'
                elif not samples:error='音频后端结束前没有有效播放位置'
                else:error=''
                with self.lock:
                    if self.audio is proc and self.audio_generation==generation:
                        self.audio_state.update({'status':'error' if error else 'ended','playing':False,'process_alive':proc.poll() is None,'exit_code':code,'error':error})
                self.event('media_backend_exit:generation=%d:code=%s:eos=%d:samples=%d:error=%s'%(generation,str(code),int(eos),samples,error))
        except Exception as e:
            reader_error='音频位置读取失败：'+type(e).__name__
            with self.lock:
                if self.audio is proc and self.audio_generation==generation and not stop_reader.is_set():
                    self.audio_state.update({'status':'error','playing':False,'error':reader_error})
            self.event('media_backend_reader_error:generation=%d:%s'%(generation,type(e).__name__))
        finally:
            for stream in (proc.stdout,proc.stderr,stdout_log,stderr_log):
                try:stream.close()
                except Exception:pass
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
        if ver not in ('HTTP/1.0','HTTP/1.1') or path not in ('/api/state','/api/audio','/api/bt-state','/api/media','/api/action'):raise ValueError('path')
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
            paths=[];media=catalog(self.root,paths)
            with self.lock:self.cached['media']=media;self.media_paths=paths
            return {'message':'媒体列表已刷新'}
        if name=='media_stop':
            self.stop_audio();return {'message':'音频已停止'}
        if name.startswith('media_play:'):
            fields=name.split(':')
            if len(fields)!=3:raise ValueError('音频参数无效')
            index=int(fields[1]);volume=int(fields[2])
            if volume<0 or volume>100:raise ValueError('音量范围无效')
            with self.lock:
                if index<0 or index>=len(self.media_paths) or self.cached['media'][index]['kind']!='audio':raise ValueError('音频不存在')
                path=self.media_paths[index]
            self.stop_audio()
            gst=next((p for p in ('/usr/bin/gst-play-1.0','/bin/gst-play-1.0') if os.path.isfile(p)),None)
            if not gst:raise RuntimeError('系统音频后端不可用')
            with self.lock:
                self.audio_generation+=1;generation=self.audio_generation
                self.audio_state=self.new_audio_state(generation,'starting')
            stdout_log=None;stderr_log=None
            try:
                stdout_log=open(self.logs+'/audio-%06d.stdout.log'%generation,'xb',buffering=0)
                stderr_log=open(self.logs+'/audio-%06d.stderr.log'%generation,'xb',buffering=0)
            except Exception as e:
                if stdout_log is not None:stdout_log.close()
                with self.lock:self.audio_state.update({'status':'error','error':'无法创建音频日志：'+type(e).__name__})
                raise
            args=[gst,'--no-interactive','--audiosink=pulsesink','--volume=%.2f'%(volume/100.0),path_url(path)]
            environment=dict(os.environ);environment['LC_ALL']='C'
            try:proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,env=environment)
            except Exception as e:
                stdout_log.close();stderr_log.close()
                with self.lock:self.audio_state.update({'status':'error','error':'音频后端无法启动：'+type(e).__name__})
                raise
            stop_reader=threading.Event();reader=threading.Thread(target=self.read_audio,args=(proc,generation,stop_reader,stdout_log,stderr_log));reader.daemon=True
            with self.lock:
                self.audio=proc;self.audio_reader=reader;self.audio_reader_stop=stop_reader;self.audio_state['process_alive']=True
                response=dict(self.audio_state)
            try:reader.start()
            except Exception as e:
                with self.lock:self.audio_reader=None
                self.stop_audio()
                for stream in (proc.stdout,proc.stderr,stdout_log,stderr_log):
                    try:stream.close()
                    except Exception:pass
                with self.lock:self.audio_state.update({'status':'error','error':'音频读取线程无法启动：'+type(e).__name__})
                raise
            self.event('media_backend_start:id=%d:volume=%d:generation=%d:position_source=gst_play_query'%(index,volume,generation))
            response['message']='音频后端启动中，等待真实播放位置'
            return response
        raise ValueError('操作不在白名单内')
    def stop_audio(self):
        with self.lock:
            proc=self.audio;reader=self.audio_reader;stop_reader=self.audio_reader_stop
            self.audio=None;self.audio_reader=None;self.audio_reader_stop=None
            self.audio_state=self.new_audio_state(self.audio_generation,'stopped')
        if stop_reader is not None:stop_reader.set()
        if proc is not None and proc.poll() is None:
            try:proc.terminate()
            except ProcessLookupError:pass
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:proc.kill()
                except ProcessLookupError:pass
                proc.wait(timeout=1)
        if reader is not None:
            reader.join(timeout=1)
            if reader.is_alive():raise RuntimeError('音频读取线程尚未停止')
    def run(self):
        config='.pragma library\nvar endpoint = '+J.dumps('http://'+self.host)+';\nvar token = '+J.dumps(self.token)+';\n'
        atomic(self.root+'/pages/Session.js',config.encode('utf-8'));self.thread.start();atomic(self.logs+'/tools.ready',b'READY\n')
        self.event('bridge_started_loopback_token_required');last_save=0
        try:
            while not STOP and time.monotonic()-self.started<1200:
                if os.path.isfile(self.logs+'/stop.request'):break
                self.service.tick()
                if not self.audio_snapshot()['process_alive'] and time.monotonic()-last_save>10:
                    atomic(self.logs+'/tools-snapshot.json',J.dumps(self.snapshot(),indent=2).encode('utf-8'));last_save=time.monotonic()
                try:c,peer=self.s.accept()
                except socket.timeout:continue
                try:
                    self.requests+=1
                    if self.requests>8000:raise RuntimeError('request ceiling')
                    method,path,body=self.parse(c)
                    if method=='GET' and path=='/api/state':payload=self.snapshot()
                    elif method=='GET' and path=='/api/audio':payload=self.audio_snapshot()
                    elif method=='GET' and path=='/api/bt-state':payload=M.bluez_scan_state()
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
            self.stop_audio();self.stop_sampler=True;errors=self.service.close();self.thread.join(timeout=1);self.s.close()
            atomic(self.logs+'/tools-finished.json',J.dumps({'errors':errors,'requests':self.requests,'config_restore_and_ssh_cleanup_ok':not errors},indent=2).encode('utf-8'))
            self.event('bridge_finished')
            if errors:raise RuntimeError('; '.join(errors))

if __name__=='__main__':
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stopping)
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    try:Bridge(os.path.realpath(os.path.dirname(__file__))).run()
    except Exception as e:print(type(e).__name__+': '+str(e),file=sys.stderr);sys.exit(1)
