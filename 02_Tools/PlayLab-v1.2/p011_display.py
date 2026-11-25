# -*- coding: utf-8 -*-
"""PlayLab 1.2 geometry/PNG helpers. Python 3.5, no external Python modules.
Renderer pixels and window coordinates are deliberately kept separate.
"""
import ctypes as C
import math
import os
import time
import p011_json as json


def bind(lib, name, result, args):
    f = getattr(lib, name)
    f.restype = result
    f.argtypes = args
    return f


class Geometry(object):
    def __init__(self, window_w, window_h, output_w, output_h, angle=0, fit='p011'):
        sizes = (window_w, window_h, output_w, output_h)
        if min(sizes) < 1 or max(sizes) > 4096:
            raise ValueError('Unusable window/renderer dimensions: {}'.format(sizes))
        self.ww, self.wh, self.ow, self.oh = sizes
        self.angle = int(angle) % 360
        if self.angle not in (0, 90, 180, 270):
            raise ValueError('Only quarter turns supported')
        self.cw, self.ch = 800, (480 if fit == 'p011' else 268)
        self.cy = (self.ch - 268) // 2
        bw, bh = (self.ch, self.cw) if self.angle % 180 else (self.cw, self.ch)
        scale = min(float(self.ow) / bw, float(self.oh) / bh)
        self.rw = max(1, int(round(self.cw * scale)))
        self.rh = max(1, int(round(self.ch * scale)))
        self.x, self.y = (self.ow - self.rw) // 2, (self.oh - self.rh) // 2
        self.cx, self.cy_render = self.x + self.rw / 2.0, self.y + self.rh / 2.0
        self.cos, self.sin = ((1, 0), (0, 1), (-1, 0), (0, -1))[self.angle // 90]

    def content_to_output(self, x, y):
        dx = (x - self.cw / 2.0) * self.rw / self.cw
        dy = (y + self.cy - self.ch / 2.0) * self.rh / self.ch
        return (self.cx + self.cos * dx - self.sin * dy,
                self.cy_render + self.sin * dx + self.cos * dy)

    def output_to_content(self, x, y):
        dx, dy = x - self.cx, y - self.cy_render
        return ((self.cos * dx + self.sin * dy) * self.cw / self.rw + self.cw / 2.0,
                (-self.sin * dx + self.cos * dy) * self.ch / self.rh + self.ch / 2.0 - self.cy)

    def window_to_content(self, x, y):
        return self.output_to_content(x * self.ow / self.ww, y * self.oh / self.wh)

    def normalized_to_content(self, x, y):
        return self.output_to_content(x * self.ow, y * self.oh)

    def active_box(self):
        points = [self.content_to_output(x, y) for x, y in ((0, 0), (800, 0), (0, 268), (800, 268))]
        x0 = max(0, int(math.floor(min(p[0] for p in points))))
        y0 = max(0, int(math.floor(min(p[1] for p in points))))
        x1 = min(self.ow, int(math.ceil(max(p[0] for p in points))))
        y1 = min(self.oh, int(math.ceil(max(p[1] for p in points))))
        return [x0, y0, max(0, x1-x0), max(0, y1-y0)]

    def data(self):
        return {'window': [self.ww, self.wh], 'renderer_output': [self.ow, self.oh],
                'angle_clockwise': self.angle, 'canvas': [self.cw, self.ch],
                'content_rect_in_canvas': [0, self.cy, 800, 268],
                'destination_before_rotation': [self.x, self.y, self.rw, self.rh],
                'projected_content_rect': self.active_box(),
                'mapping': 'event(window or normalized) -> renderer pixels -> inverse texture transform -> content',
                'panel_crop_note': 'projected application content, NOT a verified physical-panel crop'}


def write_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=True, indent=2))


def save_argb_png(buffer, width, height, path, crop=None):
    """Native-endian ARGB/XRGB buffer -> opaque PNG using existing libcairo.
    Pixel stride is width*4. No Pillow/json/zlib Python dependency.
    """
    lib = C.CDLL('libcairo.so.2')
    V, I, D = C.c_void_p, C.c_int, C.c_double
    create = bind(lib, 'cairo_image_surface_create_for_data', V, [V, I, I, I, I])
    create_empty = bind(lib, 'cairo_image_surface_create', V, [I, I, I])
    status = bind(lib, 'cairo_surface_status', I, [V])
    destroy = bind(lib, 'cairo_surface_destroy', None, [V])
    write = bind(lib, 'cairo_surface_write_to_png', I, [V, C.c_char_p])
    surface = create(buffer, 1, width, height, width*4)  # RGB24 ignores undefined alpha.
    extra = None
    try:
        if not surface or status(surface):
            raise RuntimeError('Cairo rejected screenshot pixel buffer')
        target = surface
        if crop is not None:
            x, y, w, h = [int(v) for v in crop]
            if min(x, y) < 0 or min(w, h) < 1 or x+w > width or y+h > height:
                raise ValueError('Invalid PNG crop')
            extra = create_empty(1, w, h)
            if not extra or status(extra):
                raise RuntimeError('Cairo screenshot crop unavailable')
            ctx = bind(lib, 'cairo_create', V, [V])(extra)
            try:
                bind(lib, 'cairo_set_source_surface', None, [V, V, D, D])(ctx, surface, -x, -y)
                bind(lib, 'cairo_paint', None, [V])(ctx)
            finally:
                bind(lib, 'cairo_destroy', None, [V])(ctx)
            target = extra
        rc = write(target, os.fsencode(path))
        if rc:
            raise RuntimeError('PNG write failed, Cairo status {}'.format(rc))
    finally:
        if extra:
            destroy(extra)
        if surface:
            destroy(surface)


def escape_html(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


class Recorder(object):
    """Own application recording, not global input logging or camera capture."""
    def __init__(self, directory, interval=10, max_shots=40):
        self.directory = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.events = open(os.path.join(directory, 'events.jsonl'), 'w', encoding='utf-8')
        self.interval, self.max_shots = interval, max_shots
        self.shots, self.count, self.bytes = [], 0, 0
        self.last_shot, self.last_periodic = -100.0, -100.0
        self.event_count = 0

    def event(self, name, data):
        if self.event_count >= 4096:
            return
        entry = {'time': time.time(), 'event': name, 'data': data}
        self.events.write(json.dumps(entry, ensure_ascii=True) + '\n')
        self.events.flush()
        self.event_count += 1

    def capture(self, api, renderer, painter, geometry, page, reason, now):
        if self.count >= self.max_shots or self.bytes >= 64*1024*1024:
            self.event('capture_limit', {'max_shots': self.max_shots})
            return None
        self.count += 1
        stem = '{:03d}-{}-{}'.format(self.count, time.strftime('%H%M%S'), page)
        meta = {'schema': 'p011.screenshot.v1.2', 'time': time.time(), 'reason': reason,
                'page': page, 'geometry': geometry.data(), 'files': {},
                'source': 'PlayLab renderer BEFORE SDL_RenderPresent; not Weston/compositor readback',
                'not_captured': 'Other windows, hardware overlays and final physical-panel crop'}
        files = meta['files']
        try:
            canvas_path = os.path.join(self.directory, stem+'-canvas.png')
            save_argb_png(painter.buf, painter.w, painter.h, canvas_path)
            files['canvas'] = os.path.basename(canvas_path)
            active_path = os.path.join(self.directory, stem+'-ui.png')
            save_argb_png(painter.buf, painter.w, painter.h, active_path, [0, geometry.cy, 800, 268])
            files['ui'] = os.path.basename(active_path)
            pixels = C.create_string_buffer(geometry.ow*geometry.oh*4)
            if api['SDL_RenderReadPixels'](renderer, None, 0x16362004, pixels, geometry.ow*4) != 0:
                msg = (api['SDL_GetError']() or b'unknown').decode('utf-8', 'replace')
                raise RuntimeError('SDL_RenderReadPixels: '+msg)
            render_path = os.path.join(self.directory, stem+'-render.png')
            save_argb_png(pixels, geometry.ow, geometry.oh, render_path)
            files['render'] = os.path.basename(render_path)
        except Exception as error:
            meta['capture_error'] = str(error)
            self.event('capture_error', {'message': str(error), 'stem': stem})
        write_json(os.path.join(self.directory, stem+'.json'), meta)
        for file in files.values():
            self.bytes += os.path.getsize(os.path.join(self.directory, file))
        self.shots.append(meta)
        self.last_shot = now
        self.event('screenshot', {'stem': stem, 'reason': reason, 'files': files})
        self.gallery()
        print('SCREENSHOT: {} ({})'.format(stem, reason), flush=True)
        return stem

    def gallery(self):
        entries = []
        for s in self.shots:
            parts = []
            for key, title in [('ui', '界面内容（不代表屏幕最终输出）'),
                               ('canvas', '应用画布'), ('render', '渲染器读回（提交给 Wayland 前）')]:
                fn = s['files'].get(key)
                if fn:
                    parts.append('<figure><figcaption>'+title+'</figcaption><a href="'+escape_html(fn)+'"><img src="'+escape_html(fn)+'"></a></figure>')
            entries.append('<section><h2>'+escape_html(s['page']+' / '+s['reason'])+'</h2><pre>'+escape_html(json.dumps(s['geometry'], indent=2))+'</pre>'+''.join(parts)+'</section>')
        doc = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>P011 截屏记录</title><style>
body{margin:24px auto;max-width:1100px;padding:0 20px;font-family:system-ui,sans-serif;background:#101722;color:#e3ebf4}section{border-top:1px solid #405369;padding:20px 0}figure{margin:15px 0}img{max-width:100%;max-height:650px;object-fit:contain;background:#000}pre{white-space:pre-wrap}figcaption{margin:8px 0;color:#a5bbd2}h1{font-size:27px}</style><h1>P011 截屏与显示记录</h1><p>这些图片来自 PlayLab 自身。render 是实际渲染器像素，canvas/ui 是程序画布；均不保证等于合成器裁切、旋转之后的物理屏幕，也不包含其他应用。</p>'''+''.join(entries)+'</html>'
        with open(os.path.join(self.directory, 'index.html'), 'w', encoding='utf-8') as f:
            f.write(doc)

    def close(self):
        self.gallery()
        self.events.close()
