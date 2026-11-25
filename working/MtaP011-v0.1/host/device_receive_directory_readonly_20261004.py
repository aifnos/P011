"""Read-only P011 directory-FD capability probe; never receive admission."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
PROBE_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
TARGET = r'''
import errno, os, stat, sys, time
until = time.monotonic() + 10.0
paths = ('/', '/mnt', '/mnt/data', '/mnt/data/p011-toolbox',
         '/mnt/data/p011-toolbox/user', '/mnt/data/p011-toolbox/user/Received')
rows, failure, close_errors = [], None, []
def check():
    if time.monotonic() >= until: raise ValueError('deadline')
def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
def verify():
    check()
    for index, row in enumerate(rows):
        if identity(os.fstat(row['fd'])) != row['identity']:
            raise ValueError('fd_changed')
        current = os.stat(b'/', follow_symlinks=False) if index == 0 else os.stat(
            row['name'], dir_fd=rows[index - 1]['fd'], follow_symlinks=False)
        if identity(current) != row['identity']:
            raise ValueError('directory_changed')
        check()
caps = dict((name, function in getattr(os, 'supports_dir_fd', ())) for name, function in
    (('open', os.open), ('mkdir', os.mkdir), ('stat', os.stat),
     ('rename', os.rename), ('unlink', os.unlink), ('rmdir', os.rmdir)))
caps['listdir_fd'] = os.listdir in getattr(os, 'supports_fd', ())
caps['fstatvfs'] = callable(getattr(os, 'fstatvfs', None))
try:
    if sys.platform != 'linux' or os.geteuid() != 0 or os.uname()[4] != 'armv7l':
        raise ValueError('platform')
    if not all(caps.values()): raise ValueError('directory_fd_unavailable')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    for index, path in enumerate(paths):
        check()
        name = path.rsplit('/', 1)[-1].encode('ascii') if index else b'/'
        row = dict(path=path, name=name, fd=None, identity=None, closed=False, close_attempted=False)
        rows.append(row)
        row['fd'] = os.open(name, flags) if index == 0 else os.open(name, flags, dir_fd=rows[index - 1]['fd'])
        row['identity'] = identity(os.fstat(row['fd']))
        meta = row['identity']
        expected_owner = (1000, 1000) if path == '/mnt/data' else (0, 0)
        if not stat.S_ISDIR(meta[2]) or meta[3:5] != expected_owner or meta[2] & 0o022:
            raise ValueError('directory_policy')
        if index >= 4 and stat.S_IMODE(meta[2]) != 0o700:
            raise ValueError('private_directory_mode')
        verify()
    verify()
    volume = os.fstatvfs(rows[-1]['fd'])
    if volume.f_frsize <= 0 or volume.f_bavail < 0: raise ValueError('volume_unknown')
    verify()
except BaseException as error:
    failure = type(error).__name__ + ':' + str(error)
finally:
    for row in reversed(rows):
        if row['fd'] is None: continue
        row['close_attempted'] = True
        try:
            if row['identity'] is None or identity(os.fstat(row['fd'])) != row['identity']:
                raise ValueError('close_identity_unknown')
            returned = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['closed'] = returned is None and error.errno == errno.EBADF
            if not row['closed']: raise ValueError('close_unknown')
        except BaseException as error: close_errors.append(type(error).__name__)
print('RESULT=' + repr(dict(passed=failure is None and not close_errors,
    failure=failure, capabilities=caps, observations=rows,
    close_errors=close_errors, until=until,
    created=False, deleted=False, bytes_changed=False, rf=False,
    receive=False, directory_fd_binding_issued=False)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-current', action='store_true', required=True)
    parser.parse_args()
    probe = BASE / 'host/device_probe.py'
    probe_raw = probe.read_bytes()
    if hashlib.sha256(probe_raw).hexdigest() != PROBE_PIN:
        raise ValueError('host_probe_changed')
    from device_probe import Adb
    original = Path(__file__).read_bytes()
    out = BASE / 'results' / ('receive-directory-readonly-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    (private / 'host-source.py').write_bytes(original)
    (private / 'probe-source.py').write_bytes(probe_raw)
    (private / 'target-source.py').write_bytes(TARGET.encode('ascii'))
    value, failure = None, None
    try:
        value = Adb(private).python('receive-directory-readonly', TARGET, timeout=25)
        (private / 'remote-result.json').write_text(json.dumps(value, indent=2,
            default=lambda item: item.decode('ascii') if type(item) is bytes else None) + '\n', encoding='ascii')
    except BaseException as error:
        failure = type(error).__name__
    rows = value.get('observations', []) if type(value) is dict else []
    unchanged = Path(__file__).read_bytes() == original and probe.read_bytes() == probe_raw
    passed = (failure is None and type(value) is dict and value.get('passed') is True and unchanged and
        len(rows) == 6 and all(row.get('closed') is True for row in rows))
    report = dict(passed=passed, source_unchanged=unchanged,
        capabilities=value.get('capabilities') if type(value) is dict else None,
        opened_fd_count=sum(type(row.get('fd')) is int for row in rows),
        closed_fd_count=sum(row.get('closed') is True for row in rows),
        data_owner_1000_observed=any(row.get('path') == '/mnt/data' and
            type(row.get('identity')) is tuple and len(row['identity']) == 5 and
            row['identity'][3:5] == (1000, 1000) for row in rows),
        target_failure=value.get('failure') if type(value) is dict else None,
        host_failure=failure, target_files_created=False, target_files_deleted=False,
        target_bytes_changed=False, rf=False, full_receive=False, admission=False,
        source_sha256=hashlib.sha256(original).hexdigest(),
        target_sha256=hashlib.sha256(TARGET.encode('ascii')).hexdigest(),
        raw_identifiers_included=False)
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'P011 read-only directory-FD API and six existing path components only. '
        b'Actual openat/no-follow, held FD and parent-relative metadata, fstatvfs and original FD close. '
        b'No file creation, delete, network/RF, receiver, P011 storage candidate or admission. '
        b'Private original observations retained separately.\n')
    (out / 'result.json').write_bytes(public)
    (out / 'README.txt').write_bytes(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or bundle.namelist() != ['result.json', 'README.txt'] or \
                bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
