"""PC SOURCE by default; explicit --check-device reads current DRM scanout.

Reuses only the pinned read-only PROBE literal, not the Bili trial controller.
Selects P011 by product and explicit transport even when an emulator exists.
Images/raw pixels stay private and are never included in the public ZIP.
No input, mode change, DRM master, display write, UI launch or radio action.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import traceback
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'host'))
from device_probe import Adb

PROBE_PATH = BASE.parent / 'BiliP011-v0.1/host/capture_drm_scanout.py'
PROBE_SHA = '2f8baf2c724a69faab9825f3155f79cc9b9a610a13d9967b02221733c2cf281d'


def save(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('short_write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    out = BASE / 'results' / ('ui-scanout-v1-' + ('device-' if args.check_device else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    report = dict(schema='p011-readonly-ui-scanout-v1', passed=False,
        evidence='DRM_SCANOUT' if args.check_device else 'PC_SOURCE', device_invoked=False,
        readonly_probe_sha256=PROBE_SHA, physical_screen_verified=False,
        images_private=True, ui_started=False, input_injected=False, rf_requested=False,
        framebuffer_written=False, drm_master_requested=False, captured_rows=[])
    try:
        raw = PROBE_PATH.read_bytes()
        if hashlib.sha256(raw).hexdigest() != PROBE_SHA:
            raise ValueError('probe_source_changed')
        tree = ast.parse(raw.decode('utf-8'))
        nodes = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'PROBE']
        if len(nodes) != 1:
            raise ValueError('probe_literal_unknown')
        source = 'import signal\nsignal.alarm(12)\n' + ast.literal_eval(nodes[0])
        ast.parse(source, feature_version=(3, 5))
        save(private / 'probe-source.py', source.encode('ascii'))
        if not args.check_device:
            report['passed'] = True
        else:
            from PIL import Image
            report['device_invoked'] = True
            value = Adb(private).python('readonly-ui-drm-scanout', source, timeout=20)
            if type(value) is not dict or value.get('read_only') is not True or type(value.get('rows')) is not list:
                raise ValueError('scanout_result_unknown')
            for index, row in enumerate(value['rows']):
                packed = row.pop('pixels_zlib_b64', None)
                if packed is None:
                    continue
                width, height, pitch = row['fb_width'], row['fb_height'], row['pitch']
                if not all(type(item) is int for item in (width, height, pitch)) or not (
                        0 < width <= 2048 and 0 < height <= 2048 and width * 4 <= pitch <= 16384 and pitch * height <= 16777216):
                    raise ValueError('geometry_unknown')
                pixels = zlib.decompress(base64.b64decode(packed, validate=True))
                if len(pixels) != pitch * height:
                    raise ValueError('pixels_incomplete')
                name = 'scanout-' + str(index)
                save(private / (name + '.pixels.raw'), pixels)
                image = Image.frombytes('RGB', (width, height), pixels, 'raw', 'BGRX', pitch, 1)
                path = private / (name + '.png')
                image.save(path)
                row.update(image_file=name + '.png', pixels_sha256=hashlib.sha256(pixels).hexdigest(),
                           color_interpretation='BGRX legacy32; no pixel edits')
                report['captured_rows'].append(row)
                print('PRIVATE_IMAGE=' + str(path), flush=True)
            report['passed'] = bool(report['captured_rows'])
    except Exception as error:
        report['error_type'] = type(error).__name__
        save(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    save(out / 'result.json', public)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        public_result_zip=str(bundle_path), zip_sha256=hashlib.sha256(bundle_path.read_bytes()).hexdigest())))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
