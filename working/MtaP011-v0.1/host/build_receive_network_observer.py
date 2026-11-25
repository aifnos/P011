"""Build only the new readonly ConnMan network observer; never opens ADB.

Reuses the existing ARM container and private target link dependencies. Does
not overwrite out/native or install anything on P011. No vendor libraries are
copied into the result ZIP. Build workspaces are unique and retained.
"""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
CONTAINER = 'p011-bili-build-20260923'
SOURCE = 'candidate/receive-network-observer-v1/native/mta_connman_observer.c'
SOURCE_PIN = (31977, 'cd0a54a3e4a2356854875219d17fc5a20bbcb858e636bae976c1ec1653f0c8da')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    if sys.argv[1:]:
        raise ValueError('No collect or device mode')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-network-observer-build-' + stamp)
    out.mkdir(parents=True)
    work = '/work/mta-network-observer-' + stamp
    report = {'evidence_level': 'HOST_ARM_CROSS_BUILD', 'passed': False,
        'device_tested': False, 'native_helper_executed': False, 'rf_tested': False,
        'phone_tested': False, 'restoration_verified': False, 'receive_admission': False,
        'vendor_libraries_distributed': False, 'steps': [], 'inputs': [], 'error': None}
    originals = {}

    def execute(label, argv):
        number = len(report['steps']) + 1
        process = subprocess.run(argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        stem = '%02d-%s' % (number, label)
        (out / (stem + '.stdout.raw')).write_bytes(process.stdout)
        (out / (stem + '.stderr.raw')).write_bytes(process.stderr)
        (out / (stem + '.host-exit.raw')).write_bytes(str(process.returncode).encode('ascii') + b'\n')
        report['steps'].append({'label': label, 'host_exit': process.returncode,
            'stdout_bytes': len(process.stdout), 'stdout_sha256': sha(process.stdout),
            'stderr_bytes': len(process.stderr), 'stderr_sha256': sha(process.stderr)})
        if process.returncode:
            raise RuntimeError('build_step_failed_' + label)
        return process.stdout

    try:
        for name in (SOURCE, 'native/mta_network.c',
                     'private-linksysroot/PRIVATE_LINK_ONLY.json', 'host/build_receive_network_observer.py'):
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            target = out / 'private-inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            report['inputs'].append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
        if (len(originals[SOURCE]), sha(originals[SOURCE])) != SOURCE_PIN:
            raise ValueError('new_native_source_changed')
        libraries = json.loads(originals['private-linksysroot/PRIVATE_LINK_ONLY.json'].decode('utf-8'))
        for row in libraries:
            data = (BASE / 'private-linksysroot' / Path(row['path']).name).read_bytes()
            if (len(data), sha(data)) != (row['size'], row['sha256']):
                raise ValueError('private_link_identity_changed')
        execute('toolchain', ['docker', 'exec', CONTAINER, 'arm-buildroot-linux-gnueabihf-gcc', '--version'])
        execute('workspace', ['docker', 'exec', CONTAINER, 'mkdir', '-p', work + '/src', work + '/link'])
        for index, name in enumerate((SOURCE,)):
            execute('source-%d' % index, ['docker', 'cp', str(BASE / name),
                CONTAINER + ':' + work + '/src/' + Path(name).name])
        for index, row in enumerate(libraries):
            execute('link-%d' % index, ['docker', 'cp',
                str(BASE / 'private-linksysroot' / Path(row['path']).name),
                CONTAINER + ':' + work + '/link/' + Path(row['path']).name])
        old = '/src/private-gst-linksysroot/usr/lib/'
        linked = [work + '/link/' + Path(libraries[0]['path']).name]
        linked += [old + 'lib' + name + '-2.0.so.0.5400.3' for name in ('gobject', 'gmodule', 'glib')]
        linked += [work + '/link/' + Path(row['path']).name for row in libraries[1:]]
        target = work + '/mta-connman-observer'
        execute('compile', ['docker', 'exec', CONTAINER, 'arm-buildroot-linux-gnueabihf-gcc',
            '-std=c99', '-O2', '-fPIC', '-march=armv7-a', '-mfpu=neon', '-mfloat-abi=hard',
            '-Wall', '-Wextra', '-Werror', '-Wformat=2', '-I' + work + '/src',
            '-I/src/private-gst-linksysroot/usr/include/glib-2.0',
            '-I/src/private-gst-linksysroot/usr/lib/glib-2.0/include',
            work + '/src/mta_connman_observer.c', '-o', target] + linked +
            ['-Wl,-rpath-link,' + old, '-pthread'])
        inspect = execute('readelf', ['docker', 'exec', CONTAINER,
            'arm-buildroot-linux-gnueabihf-readelf', '-h', '-d', target])
        (out / 'observer.elf.txt').write_bytes(inspect)
        destination = out / 'mta-connman-observer'
        execute('pull', ['docker', 'cp', CONTAINER + ':' + target, str(destination)])
        binary = destination.read_bytes()
        report['binary'] = {'name': destination.name, 'bytes': len(binary), 'sha256': sha(binary)}
        report['source_preserved'] = all((BASE / name).read_bytes() == raw for name, raw in originals.items())
        report['passed'] = (binary[:4] == b'\x7fELF' and b'ARM' in inspect and
            b'ELF32' in inspect and report['source_preserved'])
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'build-error-private.txt').write_text(str(error), encoding='utf-8')
    (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text(
        'New readonly ConnMan network observer ARM cross-build only. No ADB or device execution.\n'
        'Does not overwrite existing helpers, target firmware or historical results.\n'
        'Private target link dependencies reused, not distributed in this ZIP.\n'
        'No RF, receive admission, phone interoperability or restoration is proved.\n', encoding='utf-8')
    with zipfile.ZipFile(out / 'public-result.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, ensure_ascii=False))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

