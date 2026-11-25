#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P011 PlayLab 1.2. Python 3.5+, existing SDL2/Cairo/Pango libraries only.
No firmware changes, remote listeners, camera/microphone access or vendor-process kills.
Device demo is experimental; host tests do not validate the P011 display/input driver.
"""
from __future__ import print_function
# The device image does not include stdlib json. Use an app-local encoder.
import p011_json as json
import argparse, ctypes as C, glob, math, os, random, signal, stat, struct
import subprocess, sys, time, threading
from p011_display import Geometry, Recorder, write_json

HERE = os.path.dirname(os.path.abspath(__file__))
PIDFILE = os.path.join(HERE, 'demo.pid')
LOGFILE = os.path.join(HERE, 'demo.log')

def textfile(path, limit=16384):
    try:
        with open(path, 'rb') as f:
            return f.read(limit).decode('utf-8', 'replace')
    except (OSError, IOError) as e:
        return '[unavailable: {}]'.format(e.strerror)

def z03_environment():
    found = {}
    for p in glob.glob('/proc/[0-9]*'):
        if textfile(p + '/comm', 64).strip() != 'Z03':
            continue
        try:
            with open(p + '/environ', 'rb') as f:
                items = f.read(65536).split(b'\0')
            for x in items:
                k, sep, v = x.partition(b'=')
                key = k.decode('ascii', 'ignore')
                if sep and key in ('XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'QT_QPA_PLATFORM'):
                    found[key] = v.decode('utf-8', 'replace')
        except (OSError, IOError):
            pass
        break
    return found

def prepare_env():
    env = os.environ.copy()
    env.update(z03_environment())
    env.setdefault('XDG_RUNTIME_DIR', '/run/user/0')
    if not env.get('WAYLAND_DISPLAY'):
        sockets = []
        for p in glob.glob(env['XDG_RUNTIME_DIR'] + '/wayland-*'):
            try:
                if stat.S_ISSOCK(os.stat(p).st_mode): sockets.append(p)
            except OSError: pass
        sockets.sort()
        if len(sockets) != 1:
            raise RuntimeError('Expected one Wayland socket; run Inventory first. Found: {}'.format(sockets))
        env['WAYLAND_DISPLAY'] = os.path.basename(sockets[0])
    return env

def command_result(args, env=None, seconds=4):
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        try: out = p.communicate(timeout=seconds)[0]
        except subprocess.TimeoutExpired:
            p.kill(); out = p.communicate()[0]
            return '[query timeout]\n' + out[:32768].decode('utf-8', 'replace')
        return out[:32768].decode('utf-8', 'replace')
    except (OSError, IOError) as e: return '[unavailable: {}]'.format(e)

def find_tool(name):
    for d in ('/usr/bin','/usr/sbin','/bin','/sbin','/usr/lib/qt5/bin'):
        p=d+'/'+name
        if os.path.isfile(p) and os.access(p, os.X_OK): return p
    return None

def library(name):
    return C.CDLL(name)

def function(lib, name, ret, args):
    f = getattr(lib, name); f.restype = ret; f.argtypes = args; return f

def sdl_inventory():
    try:
        l=library('libSDL2-2.0.so.0')
        num=function(l,'SDL_GetNumVideoDrivers',C.c_int,[])()
        drv=function(l,'SDL_GetVideoDriver',C.c_char_p,[C.c_int])
        class Version(C.Structure): _fields_=[('major',C.c_uint8),('minor',C.c_uint8),('patch',C.c_uint8)]
        v=Version(); function(l,'SDL_GetVersion',None,[C.POINTER(Version)])(C.byref(v))
        return {'version':'{}.{}.{}'.format(v.major,v.minor,v.patch),
                'compiled_video_drivers':[drv(i).decode('ascii','replace') for i in range(num)]}
    except Exception as e: return {'error':str(e)}

def inventory():
    try: env=prepare_env(); env_status='selected'
    except Exception as e: env=os.environ.copy();env_status=str(e)
    tools=('python3','python3.5','qml','qmlscene','ffmpeg','ffplay','gst-launch-1.0',
           'gst-play-1.0','gst-inspect-1.0','aplay','arecord','tinyplay','tinycap','pactl',
           'weston-info','weston-image','weston-flower','connmanctl','sshd','opkg')
    files=('/usr/lib/libQt5WebEngineCore.so.5.10.1','/usr/lib/qt5/libexec/QtWebEngineProcess',
           '/usr/lib/libSDL2-2.0.so.0.8.0','/usr/lib/libocr_engine.so','/usr/lib/libcamv4l2adapter.so',
           '/usr/lib/libcairo.so.2','/usr/lib/libpangocairo-1.0.so.0')
    mem=textfile('/proc/meminfo',8192)
    result={'schema':'p011.inventory.v1.1', 'tool':'P011 PlayLab 1.1 inventory', 'python':sys.version, 'uid':os.getuid(),
            'system':textfile('/etc/os-release'), 'kernel':os.uname().release, 'machine':os.uname().machine,
            'memory':'\n'.join(x for x in mem.splitlines() if x.startswith(('MemTotal:','MemAvailable:','SwapTotal:','SwapFree:'))),
            'load':textfile('/proc/loadavg',128).strip(), 'mounts':textfile('/proc/mounts',32768),
            'wayland_selection':env_status,'graphics_environment':{k:env[k] for k in ('XDG_RUNTIME_DIR','WAYLAND_DISPLAY') if k in env},
            'tools':{n:find_tool(n) for n in tools},'libraries':{p:os.path.exists(p) for p in files},
            'sdl':sdl_inventory(), 'display_config':textfile('/usr/share/weston.config'),
            'devices':sorted(glob.glob('/dev/video*')+glob.glob('/dev/media*')+glob.glob('/dev/dri/*')+glob.glob('/dev/snd/*'))}
    result['input_names']={p:textfile(p,512).strip() for p in glob.glob('/sys/class/input/event*/device/name')}
    result['framebuffers']={p:textfile(p,512).strip() for p in glob.glob('/sys/class/graphics/fb*/virtual_size')}
    result['process_names']=sorted(set(textfile(p,128).strip() for p in glob.glob('/proc/[0-9]*/comm')))
    result['capture_candidates']={}
    for p in ('/home/user/takepic','/home/user/wordpic','/home/userdata/temp/pre.jpg','/home/userdata/camera_qa'):
        try:
            st=os.stat(p); result['capture_candidates'][p]={'exists':True,'is_directory':stat.S_ISDIR(st.st_mode),'size':st.st_size,'mtime':st.st_mtime}
        except OSError: result['capture_candidates'][p]={'exists':False}
    for name,argv in [('weston-info',[]),('aplay',['-l']),('ffmpeg',['-version']),('gst-inspect-1.0',['waylandsink'])]:
        exe=find_tool(name)
        if exe: result['query_'+name]=command_result([exe]+argv,env)
    result['privacy']='No serial numbers, whole process environments, Wi-Fi configs, OCR text, images, user databases or authentication files collected. Device paths and process names are included.'
    print(json.dumps(result,ensure_ascii=True,indent=2))

class Rect(C.Structure): _fields_=[('x',C.c_int),('y',C.c_int),('w',C.c_int),('h',C.c_int)]
class DisplayMode(C.Structure): _fields_=[('format',C.c_uint32),('w',C.c_int),('h',C.c_int),('refresh',C.c_int),('data',C.c_void_p)]
# SDL2 events are 56 bytes on the target ABI; use 64 bytes with 64-bit alignment.
class Event(C.Union): _fields_=[('kind',C.c_uint32),('align',C.c_uint64),('raw',C.c_ubyte*64)]

class Painter(object):
    def __init__(self,w,h):
        self.w,self.h=w,h; self.buf=C.create_string_buffer(w*h*4)
        self.c=library('libcairo.so.2'); self.pc=library('libpangocairo-1.0.so.0')
        self.p=library('libpango-1.0.so.0'); self.g=library('libgobject-2.0.so.0')
        self.surface=function(self.c,'cairo_image_surface_create_for_data',C.c_void_p,[C.c_void_p,C.c_int,C.c_int,C.c_int,C.c_int])(self.buf,0,w,h,w*4)
        if function(self.c,'cairo_surface_status',C.c_int,[C.c_void_p])(self.surface): raise RuntimeError('Cairo surface unavailable')
        self.ctx=function(self.c,'cairo_create',C.c_void_p,[C.c_void_p])(self.surface)
        for n,args in [('set_source_rgb',[C.c_double]*3),('rectangle',[C.c_double]*4),('move_to',[C.c_double]*2),('line_to',[C.c_double]*2),('set_line_width',[C.c_double]),('arc',[C.c_double]*5),('save',[]),('restore',[]),('translate',[C.c_double]*2),('fill',[]),('stroke',[]),('paint',[])]:
            setattr(self,n,function(self.c,'cairo_'+n,None,[C.c_void_p]+args))
        self.layout=function(self.pc,'pango_cairo_create_layout',C.c_void_p,[C.c_void_p])(self.ctx)
        self.font=function(self.p,'pango_font_description_from_string',C.c_void_p,[C.c_char_p])(b'Source Han Sans SC')
        self.font_size=function(self.p,'pango_font_description_set_absolute_size',None,[C.c_void_p,C.c_double])
        self.font_set=function(self.p,'pango_layout_set_font_description',None,[C.c_void_p,C.c_void_p])
        self.text_set=function(self.p,'pango_layout_set_text',None,[C.c_void_p,C.c_char_p,C.c_int])
        self.show=function(self.pc,'pango_cairo_show_layout',None,[C.c_void_p,C.c_void_p])
        self.flush=function(self.c,'cairo_surface_flush',None,[C.c_void_p])
    def color(self,rgb): self.set_source_rgb(self.ctx,*[v/255.0 for v in rgb])
    def box(self,x,y,w,h,rgb): self.color(rgb);self.rectangle(self.ctx,x,y,w,h);self.fill(self.ctx)
    def label(self,text,x,y,size=22,color=(226,232,240)):
        self.color(color); self.move_to(self.ctx,x,y); self.font_size(self.font,size*1024.0)
        self.font_set(self.layout,self.font); self.text_set(self.layout,text.encode('utf-8'),-1);self.show(self.ctx,self.layout)
    def line(self,x1,y1,x2,y2,color,width=3):
        self.color(color);self.set_line_width(self.ctx,width);self.move_to(self.ctx,x1,y1);self.line_to(self.ctx,x2,y2);self.stroke(self.ctx)
    def close(self):
        function(self.g,'g_object_unref',None,[C.c_void_p])(self.layout)
        function(self.p,'pango_font_description_free',None,[C.c_void_p])(self.font)
        function(self.c,'cairo_destroy',None,[C.c_void_p])(self.ctx)
        function(self.c,'cairo_surface_destroy',None,[C.c_void_p])(self.surface)

class Model(object):
    def __init__(self):
        self.page='home';self.cal_hits=set();self.timer_left=60.0;self.timer_on=False;self.reset_snake()
    def reset_snake(self):
        self.snake=[(12,5),(11,5),(10,5)];self.direction=(1,0);self.queued=(1,0)
        self.play=False;self.dead=False;self.score=0;self.tick=0;self.food=self.new_food()
    def new_food(self):
        choices=[(x,y) for y in range(11) for x in range(36) if (x,y) not in self.snake]
        return random.choice(choices) if choices else None
    def turn(self,d):
        if d[0]+self.direction[0]!=0 or d[1]+self.direction[1]!=0:self.queued=d
    def update(self,dt):
        if self.timer_on:
            self.timer_left=max(0,self.timer_left-dt)
            if self.timer_left==0:self.timer_on=False
        if self.page!='snake' or not self.play:return
        self.tick+=dt
        if self.tick<0.16:return
        self.tick=0;self.direction=self.queued
        head=(self.snake[0][0]+self.direction[0],self.snake[0][1]+self.direction[1])
        eat=head==self.food
        if not (0<=head[0]<36 and 0<=head[1]<11) or head in (self.snake if eat else self.snake[:-1]):
            self.dead=True;self.play=False;return
        self.snake.insert(0,head)
        if eat:
            self.score+=1;self.food=self.new_food()
            if self.food is None:self.play=False
        else:self.snake.pop()

ACCENT=(47,211,174); BG=(14,20,31); CARD=(28,39,55); MUTED=(149,165,184)

def draw(p,m,remain,content_y):
    c=p.ctx;p.box(0,0,p.w,p.h,(0,0,0));p.save(c);p.translate(c,0,content_y);p.box(0,0,800,268,BG)
    p.label({'home':'P011  ·  游乐场','clock':'时钟','timer':'一分钟计时','snake':'贪吃蛇','calibrate':'显示与触摸'}[m.page],24,10,28)
    p.label('{} 秒'.format(int(math.ceil(remain))),355,20,16,MUTED)
    p.box(434,12,72,38,CARD);p.label('校准',447,17,20)
    p.box(518,12,72,38,CARD);p.label('截屏',531,17,20)
    p.box(603,12,83,38,CARD);p.label('返回',620,17,20)
    p.box(701,12,76,38,(71,41,46));p.label('退出',715,17,20)
    if m.page=='calibrate':
        p.line(1,1,798,1,ACCENT,2);p.line(798,1,798,266,ACCENT,2)
        p.line(798,266,1,266,ACCENT,2);p.line(1,266,1,1,ACCENT,2)
        p.line(400,62,400,248,(59,77,96),1)
        p.line(22,154,778,154,(59,77,96),1)
        for num,x,y in [(1,65,93),(2,735,93),(3,65,220),(4,735,220)]:
            color=ACCENT if num in m.cal_hits else (79,142,202)
            p.box(x-37,y-24,74,48,color)
            p.label(str(num),x-8,y-21,28,(8,23,30))
        p.label('四个角标与外框应完整可见',185,89,25)
        p.label('依次点击 1、2、3、4；命中后变绿',164,138,21,MUTED)
        p.label('800 × 268  活动区 / 点击“返回”进入工具',163,187,19,MUTED)
    elif m.page=='home':
        p.label('独立运行 · 不替换原厂界面',24,49,16,MUTED)
        for i,(num,title,desc) in enumerate([('01','时钟','日期与时间'),('02','短计时','暂停 / 重置'),('03','贪吃蛇','触屏 / 滑动')]):
            x=24+i*255;p.box(x,90,240,139,CARD);p.label(num,x+16,99,18,ACCENT)
            p.label(title,x+16,129,29);p.label(desc,x+16,181,18,MUTED)
        p.label('首次试验将在倒计时结束后自动退出',24,242,15,MUTED)
    elif m.page=='clock':
        p.label(time.strftime('%H:%M:%S'),58,64,92,ACCENT);p.label(time.strftime('%Y / %m / %d'),590,102,20)
        p.label('以学习笔当前系统时间为准',590,142,14,MUTED)
    elif m.page=='timer':
        n=int(math.ceil(m.timer_left));p.label('{:02d}:{:02d}'.format(n//60,n%60),54,68,97,ACCENT)
        p.box(480,96,130,70,CARD);p.label('暂停' if m.timer_on else '开始',515,115,25)
        p.box(632,96,130,70,CARD);p.label('重置',666,115,25)
        p.label('仅视觉计时，不录音、不播放声音',480,193,16,MUTED)
    else:
        p.label('得分 {}'.format(m.score),222,18,19,ACCENT)
        p.box(22,78,544,169,CARD)
        for x,y in m.snake:p.box(24+x*15,80+y*15,13,13,ACCENT)
        if m.food:
            x,y=m.food;p.box(24+x*15,80+y*15,13,13,(255,165,90))
        if not m.play:
            p.box(132,131,334,59,(39,57,76));p.label('结束了 · 点开始重来' if m.dead else '点右侧开始，滑动转向',145,146,21)
        for x,y,w,h,label in [(632,65,65,40,'↑'),(565,110,65,45,'←'),(699,110,65,45,'→'),(632,163,65,40,'↓')]:
            p.box(x,y,w,h,CARD);p.label(label,x+23,y+2,29)
        p.box(602,216,150,35,CARD);p.label('暂停' if m.play else '开始',651,220,20)
    p.restore(c);p.flush(p.surface)

def clicked(m,x,y):
    if 434<=x<=506 and 12<=y<=50:m.page='calibrate';m.play=False;return True
    if m.page=='calibrate':
        for num,a,b in [(1,65,93),(2,735,93),(3,65,220),(4,735,220)]:
            if abs(x-a)<=37 and abs(y-b)<=24:m.cal_hits.add(num)
    if 701<=x<=777 and 12<=y<=50:return False
    if 603<=x<=686 and 12<=y<=50:m.page='home';m.play=False;return True
    if m.page=='home' and 90<=y<=229:
        for i,page in enumerate(('clock','timer','snake')):
            if 24+i*255<=x<=264+i*255:m.page=page
    elif m.page=='timer':
        if 480<=x<=610 and 96<=y<=166:
            if m.timer_left==0:m.timer_left=60
            m.timer_on=not m.timer_on
        if 632<=x<=762 and 96<=y<=166:m.timer_on=False;m.timer_left=60
    elif m.page=='snake':
        for a,b,w,h,d in [(632,65,65,40,(0,-1)),(565,110,65,45,(-1,0)),(699,110,65,45,(1,0)),(632,163,65,40,(0,1))]:
            if a<=x<=a+w and b<=y<=b+h:m.turn(d)
        if 602<=x<=752 and 216<=y<=251:
            if m.dead:m.reset_snake()
            m.play=not m.play
    return True

def stop_own_demo():
    try:
        pid=int(textfile(PIDFILE,32).strip())
        with open('/proc/{}/cmdline'.format(pid),'rb') as f:cmd=f.read(8192).split(b'\0')
        if os.path.abspath(__file__).encode('utf-8') not in cmd or b'--demo' not in cmd:
            raise RuntimeError('PID does not belong to this demo; nothing was signalled.')
        os.kill(pid,signal.SIGTERM); print('Stop requested for PlayLab PID {}'.format(pid))
    except (ValueError, OSError, IOError) as e:print('No running demo confirmed: {}'.format(e))

def request_own_capture(request_id):
    import re
    if not re.match(r'^[0-9-]{8,40}$', request_id):
        raise ValueError('Invalid screenshot request ID')
    pid=int(textfile(PIDFILE,32).strip())
    with open('/proc/{}/cmdline'.format(pid),'rb') as f:
        argv=f.read(8192).split(b'\0')
    if os.path.abspath(__file__).encode('utf-8') not in argv or b'--demo' not in argv:
        raise RuntimeError('No running PlayLab 1.2 demo confirmed. This is not a global screenshot API.')
    path=textfile(os.path.join(HERE,'active-record.txt'),1024).strip()
    if not path.startswith(HERE+'/captures/') or '..' in path or not os.path.isdir(path):
        raise RuntimeError('No valid live capture folder')
    request=os.path.join(HERE,'control',request_id+'.request')
    done=os.path.join(HERE,'control',request_id+'.done')
    fd=os.open(request,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.close(fd)
    end=time.monotonic()+12
    while time.monotonic()<end:
        if os.path.isfile(done):
            stem=textfile(done,512).strip()
            if stem.startswith('ERROR:'):raise RuntimeError(stem)
            print(json.dumps({'schema':'p011.manualshot.v1.2','capture_dir':path,'stem':stem},ensure_ascii=True))
            return
        time.sleep(0.1)
    # Leave a timed-out request for the running demo rather than signal an unknown process.
    raise RuntimeError('No screenshot completion within 12 seconds; inspect demo records.')


class RendererInfo(C.Structure):
    _fields_=[('name',C.c_char_p),('flags',C.c_uint32),('num_texture_formats',C.c_uint32),
              ('texture_formats',C.c_uint32*16),('max_texture_width',C.c_int),('max_texture_height',C.c_int)]


def demo(seconds,rotate,fit,host_test=False,record_dir=None,record_every=10,start_page='home',test_resize=False):
    if not record_dir:
        record_dir=os.path.join(HERE,'captures',time.strftime('%Y%m%d-%H%M%S'))
    if not host_test:
        if not os.path.abspath(record_dir).startswith(HERE+'/captures/') or '..' in record_dir:
            raise RuntimeError('Capture path must stay below the private app directory')
        env=prepare_env();os.environ.update(env);os.environ['SDL_VIDEODRIVER']='wayland'
        if os.path.exists(PIDFILE):
            try:
                old=int(textfile(PIDFILE,32).strip());os.kill(old,0)
                raise RuntimeError('An existing demo PID is still alive; use Stop first.')
            except (ValueError,OSError):os.unlink(PIDFILE)
        fd=os.open(PIDFILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(str(os.getpid()))
    watchdog=None
    if not host_test:
        def hard_exit():
            try:
                if textfile(PIDFILE,32).strip()==str(os.getpid()):os.unlink(PIDFILE)
            except OSError:pass
            os._exit(124)
        watchdog=threading.Timer(seconds+20,hard_exit);watchdog.daemon=True;watchdog.start()
    running=[True];signal.signal(signal.SIGTERM,lambda *_:running.__setitem__(0,False))
    s=library('libSDL2-2.0.so.0');V=C.c_void_p;I=C.c_int;U=C.c_uint32;P=C.POINTER
    api={}
    specs=[('SDL_Init',I,[U]),('SDL_Quit',None,[]),('SDL_GetError',C.c_char_p,[]),
           ('SDL_SetHint',I,[C.c_char_p,C.c_char_p]),('SDL_GetCurrentDisplayMode',I,[I,P(DisplayMode)]),
           ('SDL_CreateWindow',V,[C.c_char_p,I,I,I,I,U]),('SDL_DestroyWindow',None,[V]),
           ('SDL_GetWindowSize',None,[V,P(I),P(I)]),('SDL_SetWindowSize',None,[V,I,I]),
           ('SDL_GetRendererOutputSize',I,[V,P(I),P(I)]),('SDL_GetRendererInfo',I,[V,P(RendererInfo)]),
           ('SDL_CreateRenderer',V,[V,I,U]),('SDL_DestroyRenderer',None,[V]),
           ('SDL_CreateTexture',V,[V,U,I,I,I]),('SDL_DestroyTexture',None,[V]),
           ('SDL_UpdateTexture',I,[V,V,V,I]),('SDL_SetRenderDrawColor',I,[V,C.c_uint8,C.c_uint8,C.c_uint8,C.c_uint8]),
           ('SDL_RenderClear',I,[V]),('SDL_RenderCopyEx',I,[V,V,V,P(Rect),C.c_double,V,I]),
           ('SDL_RenderSetViewport',I,[V,P(Rect)]),('SDL_RenderSetScale',I,[V,C.c_float,C.c_float]),
           ('SDL_RenderGetViewport',None,[V,P(Rect)]),('SDL_RenderReadPixels',I,[V,P(Rect),U,V,I]),
           ('SDL_RenderPresent',None,[V]),('SDL_PollEvent',I,[P(Event)]),('SDL_RaiseWindow',None,[V])]
    for n,r,a in specs:api[n]=function(s,n,r,a)
    def check(ok):
        if not ok:raise RuntimeError('SDL: '+(api['SDL_GetError']() or b'unknown').decode('utf-8','replace'))
    window=renderer=texture=None;painter=None;rec=None
    active=os.path.join(HERE,'active-record.txt')
    control=os.path.join(HERE,'control')
    try:
        rec=Recorder(record_dir,record_every)
        if not host_test:api['SDL_SetHint'](b'SDL_RENDER_DRIVER',b'opengles2')
        api['SDL_SetHint'](b'SDL_VIDEO_MINIMIZE_ON_FOCUS_LOSS',b'0')
        check(api['SDL_Init'](0x21)==0)
        dm=DisplayMode();check(api['SDL_GetCurrentDisplayMode'](0,C.byref(dm))==0)
        # wl_output's 480x800 mode is NOT the compositor's landscape logical size.
        # Request the vendor application's 800x480 canvas, then honor actual configure events.
        requested=(800,480) if fit=='p011' else (800,268)
        if host_test and test_resize:requested=(480,800)
        flags=(4|16|32) if host_test else (0x1001|4|16|32)
        window=api['SDL_CreateWindow'](b'P011 PlayLab 1.2',0x2FFF0000,0x2FFF0000,requested[0],requested[1],flags);check(window)
        renderer=api['SDL_CreateRenderer'](window,-1,0 if host_test else 2)
        if not renderer:
            api['SDL_SetHint'](b'SDL_RENDER_DRIVER',b'software');renderer=api['SDL_CreateRenderer'](window,-1,1)
        check(renderer);api['SDL_RaiseWindow'](window)
        info=RendererInfo();check(api['SDL_GetRendererInfo'](renderer,C.byref(info))==0)
        rec.event('initial_display_mode',{'raw_mode':[dm.w,dm.h], 'requested_window':list(requested),
                  'renderer':(info.name or b'').decode('ascii','replace'), 'flags':info.flags,
                  'auto_angle_policy':'0 for P011: Weston owns the output rotation; no width<height heuristic'})
        cw,ch=800,(480 if fit=='p011' else 268);cy=(ch-268)//2
        painter=Painter(cw,ch);texture=api['SDL_CreateTexture'](renderer,0x16362004,1,cw,ch);check(texture)
        m=Model();m.page=start_page
        event=Event();start=last=time.monotonic();pressed=None;touch_seen=False
        geo=None;geo_sig=None;resize_done=False;last_size_event=None;pending_reason='first_frame';manual=[]
        if not host_test:
            os.makedirs(control,mode=0o700,exist_ok=True)
            # Never process pending requests left over from a previous session.
            for stale in glob.glob(control+'/*.request'):
                try:os.unlink(stale)
                except OSError:pass
            with open(active+'.tmp','w') as f:f.write(record_dir)
            os.replace(active+'.tmp',active)
        print('CAPTURE_DIR='+record_dir,flush=True)
        print('CAPTURE_SOURCE=own renderer before present + canvas/UI; NOT the final compositor/physical display',flush=True)
        while running[0] and time.monotonic()-start<seconds:
            now=time.monotonic();m.update(min(now-last,0.2));last=now
            events=[]
            while api['SDL_PollEvent'](C.byref(event)):
                raw=bytes(event.raw);events.append(raw)
                kind=struct.unpack_from('<I',raw,0)[0]
                if kind==0x200:
                    sub=raw[12];d1,d2=struct.unpack_from('<ii',raw,16)
                    rec.event('window_event',{'subtype':sub,'data1':d1,'data2':d2})
                    if sub in (5,6):last_size_event=[d1,d2]
            # PollEvent can dispatch Wayland configure, changing w/h AND EGL drawable size.
            # Query AFTER dispatch on every frame; never draw with creation-time dimensions.
            ww,wh,ow,oh=I(),I(),I(),I()
            api['SDL_GetWindowSize'](window,C.byref(ww),C.byref(wh))
            check(api['SDL_GetRendererOutputSize'](renderer,C.byref(ow),C.byref(oh))==0)
            angle=0 if rotate=='auto' else int(rotate)
            sig=(ww.value,wh.value,ow.value,oh.value,angle,fit)
            if sig!=geo_sig:
                geo=Geometry(ww.value,wh.value,ow.value,oh.value,angle,fit);geo_sig=sig
                check(api['SDL_RenderSetScale'](renderer,1.0,1.0)==0)
                check(api['SDL_RenderSetViewport'](renderer,None)==0)
                viewport=Rect();api['SDL_RenderGetViewport'](renderer,C.byref(viewport))
                data=geo.data();data['viewport']=[viewport.x,viewport.y,viewport.w,viewport.h];data['last_resize_event']=last_size_event
                rec.event('geometry',data);write_json(os.path.join(record_dir,'latest-geometry.json'),data)
                print('GEOMETRY: window={}x{} output={}x{} ROTATE={} dst={} viewport={} resize_event={}'.format(
                      geo.ww,geo.wh,geo.ow,geo.oh,angle,[geo.x,geo.y,geo.rw,geo.rh],data['viewport'],last_size_event),flush=True)
                pending_reason='geometry_change';pressed=None
            for raw in events:
                kind=struct.unpack_from('<I',raw,0)[0]
                if kind==0x100 or (kind==0x200 and raw[12]==14):running[0]=False
                elif kind==0x300:
                    key=struct.unpack_from('<i',raw,20)[0]
                    if key==27:running[0]=False
                    elif key in (1073741903,1073741904,1073741905,1073741906):
                        m.turn({1073741903:(1,0),1073741904:(-1,0),1073741905:(0,1),1073741906:(0,-1)}[key])
                elif kind in (0x700,0x701,0x402):
                    if kind==0x402 and touch_seen:continue
                    if kind in (0x700,0x701):
                        touch_seen=True;x,y=struct.unpack_from('<ff',raw,24)
                        if not math.isfinite(x) or not math.isfinite(y):continue
                        pt=geo.normalized_to_content(x,y);space='normalized_touch'
                    else:
                        x,y=struct.unpack_from('<ii',raw,20);pt=geo.window_to_content(x,y);space='window_mouse'
                    rec.event('pointer',{'kind':kind,'space':space,'input':[x,y],'content':[round(pt[0],3),round(pt[1],3)],'page':m.page})
                    if kind==0x700:pressed=pt;continue
                    previous=m.page
                    if 518<=pt[0]<=590 and 12<=pt[1]<=50:
                        pending_reason='screen_button'
                    elif pressed and m.page=='snake' and max(abs(pt[0]-pressed[0]),abs(pt[1]-pressed[1]))>20:
                        dx,dy=pt[0]-pressed[0],pt[1]-pressed[1]
                        m.turn((1 if dx>0 else -1,0) if abs(dx)>abs(dy) else (0,1 if dy>0 else -1))
                    else:running[0]=clicked(m,*pt)
                    pressed=None
                    if pending_reason!='screen_button':pending_reason='page_change' if previous!=m.page else 'touch'
            if test_resize and host_test and not resize_done and now-start>0.8:
                api['SDL_SetWindowSize'](window,800,480);resize_done=True
            if not host_test:
                pending=sorted(glob.glob(control+'/*.request'))
                if pending and not manual:
                    manual=[pending[0]];pending_reason='pc_request'
            draw(painter,m,max(0,seconds-(now-start)),cy)
            check(api['SDL_UpdateTexture'](texture,None,painter.buf,cw*4)==0)
            check(api['SDL_SetRenderDrawColor'](renderer,0,0,0,255)==0)
            check(api['SDL_RenderClear'](renderer)==0)
            dst=Rect(geo.x,geo.y,geo.rw,geo.rh)
            check(api['SDL_RenderCopyEx'](renderer,texture,None,C.byref(dst),angle,None,0)==0)
            # Do not save creation-time transient black/configure frames. Always capture before Present.
            if now-start>=0.65:
                if now-rec.last_periodic>=record_every and not pending_reason:pending_reason='periodic'
                if not running[0]:pending_reason='exit'
                if pending_reason and now-rec.last_shot>=0.9:
                    stem=rec.capture(api,renderer,painter,geo,m.page,pending_reason,now)
                    if pending_reason=='periodic' or rec.count==1:rec.last_periodic=now
                    if manual:
                        req=manual[0];done=req[:-len('.request')]+'.done'
                        with open(done+'.tmp','w') as f:f.write(stem or 'ERROR: screenshot limit reached')
                        os.replace(done+'.tmp',done)
                        try:os.unlink(req)
                        except OSError:pass
                        manual=[]
                    pending_reason=''
            api['SDL_RenderPresent'](renderer);time.sleep(0.05)
        print('DEMO_EXIT: own window closed. No vendor process or startup setting changed.',flush=True)
    finally:
        if rec:
            rec.event('cleanup',{'exception_pending':sys.exc_info()[0] is not None});rec.close()
        if texture:api['SDL_DestroyTexture'](texture)
        if renderer:api['SDL_DestroyRenderer'](renderer)
        if window:api['SDL_DestroyWindow'](window)
        api['SDL_Quit']()
        if painter:painter.close()
        if watchdog:watchdog.cancel()
        if not host_test:
            if textfile(PIDFILE,32).strip()==str(os.getpid()):os.unlink(PIDFILE)
            try:
                if textfile(active,1024).strip()==record_dir:os.unlink(active)
            except OSError:pass

def selftest(out=None):
    m=Model();assert clicked(m,50,130) and m.page=='clock';clicked(m,625,25);assert m.page=='home'
    clicked(m,560,135);assert m.page=='snake';m.play=True;m.food=(13,5);m.update(0.2);assert m.score==1 and len(m.snake)==4
    m.turn((-1,0));assert m.queued==(1,0)
    m.timer_on=True;m.timer_left=0.1;m.update(0.2);assert m.timer_left==0 and not m.timer_on
    assert clicked(m,732,25) is False
    if out:
        p=Painter(800,480)
        try:
            for page in ('home','clock','timer','snake','calibrate'):
                m.page=page;draw(p,m,120,106)
                function(p.c,'cairo_surface_write_to_png',C.c_int,[C.c_void_p,C.c_char_p])(p.surface,os.path.join(out,page+'.png').encode('utf-8'))
        finally:p.close()
    print('SELFTEST PASS: navigation, timer, snake and optional host rendering. NOT a P011 hardware test.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);g=parser.add_mutually_exclusive_group(required=True)
    for k in ('inventory','demo','stop','selftest','host-test','request-shot'):g.add_argument('--'+k,action='store_true')
    parser.add_argument('--seconds',type=int,default=120);parser.add_argument('--rotate',choices=('auto','0','90','180','270'),default='auto')
    parser.add_argument('--fit',choices=('p011','full'),default='p011');parser.add_argument('--preview-dir')
    parser.add_argument('--record-dir');parser.add_argument('--record-every',type=int,default=10)
    parser.add_argument('--start-page',choices=('home','calibrate'),default='home')
    parser.add_argument('--request-id');parser.add_argument('--test-resize',action='store_true')
    args=parser.parse_args()
    if not 1<=args.seconds<=600:parser.error('seconds must be 1..600')
    try:
        if not 2<=args.record_every<=120:parser.error('record-every must be 2..120 seconds')
        if args.inventory:inventory()
        elif args.stop:stop_own_demo()
        elif args.request_shot:request_own_capture(args.request_id or '')
        elif args.selftest:selftest(args.preview_dir)
        else:
            demo(args.seconds,args.rotate,args.fit,args.host_test,args.record_dir,args.record_every,args.start_page,args.test_resize)
    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
