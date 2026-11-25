#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Best-effort legacy fb0 snapshot, independently of PlayLab.
Only O_RDONLY + GET ioctls + bounded read; never SET/PAN/mmap/DRM master.
A fbdev buffer may be stale under DRM/Wayland: PNG != proven active scanout.
"""
import argparse
import ctypes as C
import os
import stat
import sys
import threading
import time
from p011_display import save_argb_png, write_json, escape_html

U32, U16, UL = C.c_uint32, C.c_uint16, C.c_ulong
class Bitfield(C.Structure):
    _fields_=[('offset',U32),('length',U32),('msb_right',U32)]
class Var(C.Structure):
    _fields_=[(n,U32) for n in ('xres','yres','xres_virtual','yres_virtual','xoffset','yoffset','bits_per_pixel','grayscale')]+[
        ('red',Bitfield),('green',Bitfield),('blue',Bitfield),('transp',Bitfield)]+[(n,U32) for n in (
        'nonstd','activate','height','width','accel_flags','pixclock','left_margin','right_margin',
        'upper_margin','lower_margin','hsync_len','vsync_len','sync','vmode','rotate','colorspace')]+[('reserved',U32*4)]
class Fix(C.Structure):
    _fields_=[('id',C.c_char*16),('smem_start',UL),('smem_len',U32),('type',U32),('type_aux',U32),('visual',U32),
              ('xpanstep',U16),('ypanstep',U16),('ywrapstep',U16),('line_length',U32),('mmio_start',UL),
              ('mmio_len',U32),('accel',U32),('capabilities',U16),('reserved',U16*2)]


def convert_fb(raw, w, h, stride, bpp, xoffset, channels):
    n=bpp//8
    if bpp not in (16,24,32) or len(raw)<stride*h or (xoffset+w)*n>stride:
        raise ValueError('Invalid framebuffer shape/stride')
    result=bytearray(w*h*4)
    for c in channels:
        if not 1<=c['length']<=8 or c['offset']+c['length']>bpp or c['msb_right']:
            raise ValueError('Unsupported RGB bitfield')
    # Target ARM and common host are little-endian. Cairo receives native-endian XRGB.
    if sys.byteorder!='little':raise RuntimeError('Little-endian path only')
    for y in range(h):
        row=raw[y*stride+xoffset*n:y*stride+(xoffset+w)*n]
        if bpp==32 and [(c['offset'],c['length']) for c in channels]==[(16,8),(8,8),(0,8)]:
            result[y*w*4:(y+1)*w*4]=row
            result[y*w*4+3:(y+1)*w*4:4]=b'\xff'*w
            continue
        for x in range(w):
            pos=x*n
            v=int.from_bytes(row[pos:pos+n],'little')
            rgb=[]
            for c in channels:
                mask=(1<<c['length'])-1
                rgb.append((((v>>c['offset'])&mask)*255+mask//2)//mask)
            d=(y*w+x)*4
            result[d:d+4]=bytes((rgb[2],rgb[1],rgb[0],255))
    return result


def snapshot(directory, index):
    path='/dev/fb0';name='fb0-{:03d}'.format(index)
    meta={'schema':'p011.fb0.v1.2','time':time.time(),'source':path,
          'active_scanout_verified':False,
          'warning':'Legacy framebuffer snapshot; may be black/stale under DRM/Wayland. Not proof of physical display contents.'}
    fd=None
    try:
        st=os.stat(path)
        if not stat.S_ISCHR(st.st_mode):raise RuntimeError('/dev/fb0 is not a character device')
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
        libc=C.CDLL(None,use_errno=True)
        ioctl=libc.ioctl;ioctl.argtypes=[C.c_int,C.c_ulong,C.c_void_p];ioctl.restype=C.c_int
        var,fix=Var(),Fix()
        if ioctl(fd,0x4600,C.byref(var))<0 or ioctl(fd,0x4602,C.byref(fix))<0:
            raise OSError(C.get_errno(),os.strerror(C.get_errno()))
        meta['geometry']={k:int(getattr(var,k)) for k in ('xres','yres','xres_virtual','yres_virtual','xoffset','yoffset','bits_per_pixel','rotate')}
        meta['stride']=int(fix.line_length);meta['smem_len']=int(fix.smem_len)
        meta['driver_id']=bytes(fix.id).decode('ascii','replace')
        meta['type'],meta['visual']=int(fix.type),int(fix.visual)
        meta['channels']=[{k:int(getattr(getattr(var,c),k)) for k in ('offset','length','msb_right')} for c in ('red','green','blue')]
        if not (0<var.xres<=2048 and 0<var.yres<=2048):raise RuntimeError('Framebuffer dimensions outside bound')
        if fix.type!=0 or fix.visual!=2 or var.nonstd or var.grayscale:
            raise RuntimeError('Only standard packed-pixel truecolor framebuffer is supported')
        if var.vmode & 256:raise RuntimeError('Y-wrapped framebuffer is not supported')
        if var.xoffset+var.xres>var.xres_virtual or var.yoffset+var.yres>var.yres_virtual:
            raise RuntimeError('Visible range is outside virtual framebuffer')
        length=int(fix.line_length)*int(var.yres);offset=int(fix.line_length)*int(var.yoffset)
        if length<=0 or length>8*1024*1024 or offset+length>fix.smem_len:
            raise RuntimeError('Framebuffer read range outside allowed memory')
        os.lseek(fd,offset,os.SEEK_SET)
        pieces=[];left=length
        while left:
            b=os.read(fd,min(left,65536))
            if not b:raise RuntimeError('Short framebuffer read')
            pieces.append(b);left-=len(b)
        raw=b''.join(pieces)
        rgba=convert_fb(raw,int(var.xres),int(var.yres),int(fix.line_length),int(var.bits_per_pixel),int(var.xoffset),meta['channels'])
        buf=C.create_string_buffer(bytes(rgba))
        png=os.path.join(directory,name+'-raw.png')
        save_argb_png(buf,int(var.xres),int(var.yres),png)
        meta['png']=os.path.basename(png);meta['status']='READ_OK_SCANOUT_UNVERIFIED'
        print('FRAMEBUFFER_READ: {} (not verified as active scanout)'.format(png),flush=True)
        return True
    except Exception as e:
        meta['status']='UNAVAILABLE';meta['error']=str(e)
        print('FRAMEBUFFER_UNAVAILABLE: '+str(e),flush=True)
        return False
    finally:
        if fd is not None:os.close(fd)
        write_json(os.path.join(directory,name+'.json'),meta)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir',required=True);p.add_argument('--shots',type=int,default=1)
    p.add_argument('--interval',type=int,default=5)
    a=p.parse_args()
    if not 1<=a.shots<=12 or not 2<=a.interval<=60:p.error('shots 1..12, interval 2..60')
    root=os.path.dirname(os.path.abspath(__file__))
    if not os.path.abspath(a.output_dir).startswith(root+'/captures/') or '..' in a.output_dir:
        raise RuntimeError('Output must remain within this app temporary directory')
    os.makedirs(a.output_dir,mode=0o700,exist_ok=True)
    # Bound even a stalled framebuffer read/ioctl; watchdog only kills this helper.
    guard=threading.Timer(a.shots*(a.interval+12)+5,lambda:os._exit(124));guard.daemon=True;guard.start()
    try:
        success=False
        for i in range(1,a.shots+1):
            ok=snapshot(a.output_dir,i)
            if not ok:break
            success=True
            if i<a.shots:time.sleep(a.interval)
        entries=[]
        for n in sorted(os.listdir(a.output_dir)):
            if n.endswith('.png'):
                entries.append('<figure><figcaption>'+escape_html(n)+'</figcaption><a href="'+escape_html(n)+'"><img style="max-width:100%;max-height:85vh" src="'+escape_html(n)+'"></a></figure>')
        with open(os.path.join(a.output_dir,'index.html'),'w',encoding='utf-8') as f:
            f.write('<!doctype html><meta charset="utf-8"><title>P011 framebuffer snapshot</title><h1>fb0 原始画面</h1><p>未核实是否为活动扫描输出。若为黑图、旧画面或方向不同，不修改系统显示设置；结合元数据分析。</p>'+''.join(entries))
        return 0 if success else 2
    finally:guard.cancel()

if __name__=='__main__':
    sys.exit(main())
