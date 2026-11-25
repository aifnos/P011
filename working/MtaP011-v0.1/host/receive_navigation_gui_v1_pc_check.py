"""One fixed SOURCE or PC build, preserved separate raw streams and scalar ZIP."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
BUILDER = BASE / 'host/build_formal_receive_filecenter_navigation_gui_v1.py'
PIN = (19656, '64a35eef8041ac3773a64aaa5412973e043cd669e9baadd2eb532788e86eaf3b')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise ValueError('pc_record_write')
    if path.read_bytes() != raw:
        raise ValueError('pc_record_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true')
    args = parser.parse_args()
    raw = BUILDER.read_bytes()
    if (len(raw), sha(raw)) != PIN:
        raise ValueError('pc_builder_pin')
    out = BASE / 'results' / ('receive-navigation-gui-v1-' +
        ('pc-build-' if args.build else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    fresh(out / 'private-builder.py', raw)
    fresh(out / 'private-recorder.py', Path(__file__).read_bytes())
    command = [sys.executable, '-I', '-B', str(BUILDER)] + (['--build'] if args.build else [])
    process = subprocess.run(command, cwd=str(BASE), capture_output=True, timeout=60)
    fresh(out / 'stdout.raw', process.stdout)
    fresh(out / 'stderr.raw', process.stderr)
    fresh(out / 'host-exit', (str(process.returncode) + '\n').encode('ascii'))
    result = dict(schema='p011-receive-navigation-gui-v1-pc-record',
        mode='PC_BUILD_ONLY' if args.build else 'SOURCE_ONLY',
        passed=False, host_exit=process.returncode, builder_pin=PIN,
        stdout_bytes=len(process.stdout), stdout_sha256=sha(process.stdout),
        stderr_bytes=len(process.stderr), stderr_sha256=sha(process.stderr),
        device=False, rf=False, navigation_verified=False, report=None,
        source_unchanged=BUILDER.read_bytes() == raw)
    if process.returncode == 0 and not process.stderr and result['source_unchanged']:
        text = process.stdout.decode('utf-8')
        report, end = json.JSONDecoder().raw_decode(text)
        suffix = text[end:].strip()
        expected = ('BUNDLE=' + report['bundle']) if args.build else ''
        if suffix != expected or report['source_ui_files'] != 17 or report['staged_file_count'] != 20 or report['planned_stage_bytes'] > 4194304:
            raise ValueError('pc_report_frame')
        result.update(passed=True, report=report)
    public = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One fixed PC-only navigation GUI SOURCE or explicit fresh build. '
        b'Separate original stdout/stderr and host exit retained. Builder input pins, '
        b'17 sources/20 assets/3 directories and original4MiB/NAV/QRC guards remain. '
        b'No runtime graph, validator, credentials, device, RF, phone, input or media. '
        b'PC build is not QtTest import, Files navigation, touch or restoration acceptance.\n')
    fresh(out / 'result.json', public)
    fresh(out / 'README.txt', readme)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.read('result.json') != public or archive.read('README.txt') != readme:
            raise ValueError('pc_zip_readback')
    print(json.dumps(dict(passed=result['passed'], mode=result['mode'],
        result_dir=str(out), bundle=result['report'].get('bundle') if result['report'] else None,
        zip_sha256=sha(bundle.read_bytes())), sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
