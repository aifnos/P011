# -*- coding: utf-8 -*-
"""Explicit legacy browser settings installation. Python 3.5.
Only the settings QRC record and root-owned external QML payload are installed.
No controller, service, vendor startup, system library or radio changes.
"""
from __future__ import print_function
import argparse
import ast
import binascii
import ctypes
import hashlib
import os
import re
import signal
import stat
import subprocess
import sys
import time
import p011_json as J
AREA = "/mnt/data/p011-browser"
SETTINGS = AREA + "/settings"
LEGACY = SETTINGS + "/legacy"
ADMIN = LEGACY + "/_install"
TARGET = "/usr/bin/Z03"
OLD = "3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896"
NEW = "b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8"
PROTECTED = {"/usr/bin/control_engine": "364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d", "/usr/bin/zyb_z03_launch.sh": "7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b"}
FIRMWARE = "z031_v2.4.0-20251128_174826-user"
CACHE = "/home/.cache/Z03/qmlcache"
CACHE_SOURCE = "qrc:/ZybQmlFiles/ZybSet/SetMainPage.qml"
RECEIPT = ADMIN + "/install-receipt.py"
LAST_TRANSACTION = None


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def read(path, limit=1048576):
    with open(path, 'rb') as handle:
        result = handle.read(limit + 1)
    require(len(result) <= limit, 'Read bound exceeded')
    return result


def sha(path):
    result = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(262144)
            if not block:
                return result.hexdigest()
            result.update(block)


def regular(path, mode=None, maximum=16777216):
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022 and info.st_size <= maximum,
            'Unsafe regular file')
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode, 'File mode differs')
    return info


def directory(path):
    require(path.startswith('/') and os.path.normpath(path) == path and
            os.path.realpath(path) == path, 'Redirected directory')
    current = ''
    for part in path.strip('/').split('/'):
        current += '/' + part
        info = os.lstat(current)
        require(stat.S_ISDIR(info.st_mode), 'Unsafe directory ancestor')
        if current == AREA or current.startswith(AREA + '/') or current.startswith('/etc/'):
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe control directory')
    return path


def new_directory(path, mode=0o700):
    require(path.startswith(AREA + '/') and os.path.normpath(path) == path,
            'New directory outside browser area')
    directory(os.path.dirname(path))
    require(not os.path.lexists(path), 'Existing directory requires inspection')
    os.mkdir(path, mode)
    os.chmod(path, mode)
    directory(path)


def literal(path, maximum=4194304):
    regular(path, 0o600, maximum)
    return ast.literal_eval(read(path, maximum).decode('utf-8'))


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic(path, data, mode=0o600, gid=0):
    directory(os.path.dirname(path))
    if os.path.lexists(path):
        regular(path)
    temp = path + '.browser-new-' + binascii.hexlify(os.urandom(8)).decode('ascii')
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(temp, 0, gid)
    os.chmod(temp, mode)
    os.replace(temp, path)
    fsync_directory(os.path.dirname(path))


def save(path, value):
    atomic(path, (repr(value) + '\n').encode('utf-8'))


def area_gate():
    directory(AREA)
    regular(AREA + '/.area-owner', 0o600, 128)
    require(read(AREA + '/.area-owner', 128) == b'p011.browser.area.v1\n', 'Browser area marker differs')


def proc(pid):
    try:
        base = '/proc/' + str(int(pid))
        raw = read(base + '/stat', 8192).decode('ascii')
        fields = raw[raw.rindex(')') + 2:].split()
        result = {'pid': int(pid), 'starttime': fields[19], 'parent': int(fields[1]),
                  'state': fields[0], 'exe': os.readlink(base + '/exe')}
        again = read(base + '/stat', 8192).decode('ascii')
        require(again[again.rindex(')') + 2:].split()[19] == result['starttime'], 'PID changed during read')
        return result
    except OSError as error:
        if error.errno in (2, 3):
            return None
        raise


def args_of(row):
    try:
        return [os.fsdecode(value) for value in read('/proc/%d/cmdline' % row['pid'], 65536).split(b'\0') if value]
    except OSError as error:
        if error.errno in (2, 3):
            return []
        raise


def process_rows():
    result = []
    for name in os.listdir('/proc'):
        if name.isdigit():
            row = proc(int(name))
            if row and row['state'] not in ('Z', 'X'):
                result.append(row)
    return result


def same_identity(left, right):
    return bool(left and right and all(str(left[key]) == str(right[key])
                for key in ('pid', 'starttime', 'parent', 'exe')))


def no_bili_session():
    services = []
    rows = process_rows()
    for row in rows:
        arguments = args_of(row)
        matches = [value for value in arguments[1:4] if re.fullmatch(
            r'/mnt/data/p011-toolbox/bili-formal/releases/[a-f0-9]{24}/app/formal_service.py', value)]
        if matches:
            services.append((row, matches[0]))
        require(not row['exe'].startswith('/mnt/data/p011-toolbox/') and
                not row['exe'].startswith(AREA + '/candidates/'), 'A native media/browser process is active')
    require(len(services) == 1, 'Formal Bili listener identity is not unique')
    row, source = services[0]
    regular(source)
    release = source.split('/releases/', 1)[1].split('/', 1)[0]
    lease = '/mnt/data/p011-toolbox/bili-awake/' + release + '/lease.json'
    regular(lease, 0o600, 8192)
    body = read(lease, 8192).decode('ascii')
    require(len(re.findall(r'"active"\s*:', body)) == 1 and
            re.search(r'"active"\s*:\s*false\s*[,}]', body) is not None and
            re.search(r'"seq"\s*:\s*-1\s*[,}]', body) is not None,
            'Bili playback lease is active or unknown')
    # The pinned FormalServer has main+monitor threads. Opening any Bili
    # session adds two Backend workers, including account-only sessions.
    require(len(os.listdir('/proc/%d/task' % row['pid'])) == 2, 'A Bili session may be active')
    require(same_identity(row, proc(row['pid'])), 'Bili listener identity changed')
    return {'pid': row['pid'], 'starttime': row['starttime'], 'source_sha256': sha(source),
            'lease_sha256': sha(lease), 'threads': 2}


def command(arguments, timeout=35, accepted=(0,)):
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        stdout, stderr = child.communicate()
        raise RuntimeError('Own installer command exceeded its deadline')
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.flush()
    require(child.returncode in accepted, 'Own installer command failed')
    return child.returncode


def remount(writable):
    command(['/bin/mount', '-o', 'remount,' + ('rw' if writable else 'ro'), '/'])
    require(('ro' not in mounts()['options']) is writable, 'Root remount was not confirmed')


def root_mode(original):
    was_ro = 'ro' in original['options']
    now_ro = 'ro' in mounts()['options']
    if now_ro != was_ro:
        remount(not was_ro)
    require(('ro' in mounts()['options']) == was_ro and
            mounts()['device'] == original['device'], 'Root mount original state not restored')


def restart_ui(row, launcher, running_hash, target_hash):
    current = proc(row['pid'])
    require(current and current['starttime'] == row['starttime'] and
            current['exe'] in (TARGET, TARGET + ' (deleted)') and
            sha('/proc/%d/exe' % row['pid']) == running_hash and
            same_identity(launcher, proc(launcher['pid'])), 'UI TERM identity differs')
    no_bili_session()
    os.kill(row['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        rows = [item for item in process_rows() if item['exe'] == TARGET]
        if len(rows) == 1 and rows[0]['starttime'] != row['starttime'] and sha('/proc/%d/exe' % rows[0]['pid']) == target_hash:
            require(same_identity(launcher, proc(rows[0]['parent'])), 'Vendor parent changed after UI reload')
            return rows[0]
        time.sleep(.15)
    raise RuntimeError('Normal UI reload was not confirmed; no forced kill')


def invalidate_cache(backup, phase):
    # Qt hashes the resource file name (":/", not "qrc:/"). Other compiled
    # pages can contain this URL as a dependency and must remain untouched.
    basename = hashlib.sha1(b':/ZybQmlFiles/ZybSet/SetMainPage.qml').hexdigest() + '.qmlc'
    require(basename == '14289f774f2ede3ee177615be7dc93a12ba1fcdb.qmlc', 'Settings cache identity differs')
    path = CACHE + '/' + basename
    if not os.path.lexists(path):
        return {'absent': True, 'path': path}
    directory(CACHE)
    require(os.path.realpath(path) == path, 'Redirected settings cache')

    def cache_info():
        info = os.lstat(path)
        # Vendor-generated qmlc files are root 0666 on this device. This
        # exception applies only to this exact cache; regular() stays strict.
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                info.st_size <= 16777216, 'Unsafe settings cache')
        return info

    def metadata(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    info = cache_info()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as handle:
        require(metadata(os.fstat(handle.fileno())) == metadata(info), 'Settings cache changed while opening')
        body = handle.read(16777217)
        require(len(body) == info.st_size and len(body) <= 16777216 and
                metadata(os.fstat(handle.fileno())) == metadata(info), 'Settings cache changed while reading')
    require(body.startswith(b'qv4cdata'), 'Unknown settings cache format')
    needles = [CACHE_SOURCE.encode('utf-8'), CACHE_SOURCE.encode('utf-16-le'), CACHE_SOURCE.encode('utf-16-be')]
    require(any(needle in body for needle in needles), 'Settings cache full source differs')
    destination = backup + '/' + phase + '-SetMainPage.qmlc'
    require(not os.path.lexists(destination), 'Cache backup already exists')
    atomic(destination, body)
    fingerprint = hashlib.sha256(body).hexdigest()
    require(sha(destination) == fingerprint, 'Settings cache backup differs')
    require(metadata(cache_info()) == metadata(info) and sha(path) == fingerprint and
            metadata(cache_info()) == metadata(info), 'Settings cache changed before invalidation')
    os.unlink(path)
    fsync_directory(CACHE)
    return {'absent': False, 'path': path, 'backup': destination, 'sha256': fingerprint,
            'mode': stat.S_IMODE(info.st_mode), 'metadata': metadata(info), 'removed': True}


def mounts():
    rows = []
    for line in read('/proc/mounts').decode('ascii').splitlines():
        values = line.split()
        if len(values) >= 4:
            rows.append({'device': values[0], 'at': values[1], 'type': values[2],
                         'options': values[3].split(',')})
    root = [row for row in rows if row['at'] == '/']
    require(len(root) == 1 and root[0]['type'] == 'ext4', 'Unsupported root mount')
    require(not any(row['at'] != '/' and TARGET.startswith(row['at'].rstrip('/') + '/')
                    for row in rows), 'Separate UI mount requires review')
    return root[0]


def core_same(before, after):
    return len(before) == len(after) and all(any(same_identity(left, right) for right in after) for left in before)


def live_gate(expected, check_bili=True):
    require(os.geteuid() == 0 and os.uname()[0] == 'Linux' and os.uname()[4] == 'armv7l', 'Not root P011 ARMv7')
    require(FIRMWARE in read('/etc/os-release', 8192).decode('ascii'), 'Firmware differs')
    area_gate()
    hashes = dict(PROTECTED)
    hashes[TARGET] = expected
    for path, fingerprint in hashes.items():
        regular(path)
        require(sha(path) == fingerprint, 'Protected file identity differs')
    rows = process_rows()
    apps = [row for row in rows if row['exe'] in (TARGET, TARGET + ' (deleted)')]
    require(len(apps) == 1, 'UI identity is not unique')
    ui = apps[0]
    require(sha('/proc/%d/exe' % ui['pid']) in (OLD, NEW), 'Running UI identity differs')
    launcher = proc(ui['parent'])
    require(launcher and '/usr/bin/zyb_z03_launch.sh' in args_of(launcher)[:3], 'Vendor UI loop differs')
    require(args_of(ui)[1:] == ['-platform', 'wayland'], 'UI arguments differ')
    cores = []
    for name in ('control_engine', 'weston'):
        selected = [row for row in rows if os.path.basename(row['exe']) == name]
        require(len(selected) == 1, 'Core process identity is not unique')
        cores.append(selected[0])
    require(all(row['state'] not in ('D', 'T', 't') for row in [ui, launcher] + cores), 'Core process is suspended or blocked')
    for path in ('/tmp/p011-menutest.lock', '/mnt/data/p011-menu'):
        require(not os.path.lexists(path), 'An old toolbox trial requires inspection')
    bili = None
    if check_bili:
        bili = no_bili_session()
        time.sleep(.25)
        require(no_bili_session() == bili, 'Bili state changed before installation')
    startup_hashes = {}
    for path in ('/etc/inittab', '/etc/init.d/rc'):
        if os.path.isfile(path):
            startup_hashes[path] = sha(path)
    return {'boot_id': read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip(),
            'hashes': hashes, 'ui': ui, 'launcher': launcher, 'core': cores,
            'mount': mounts(), 'startup_hashes': startup_hashes, 'bili_inactive': bili,
            'z03_mode': stat.S_IMODE(os.stat(TARGET).st_mode), 'z03_gid': os.stat(TARGET).st_gid}


def assert_binding(before, current):
    require(before['boot_id'] == current['boot_id'] and same_identity(before['ui'], current['ui']) and
            same_identity(before['launcher'], current['launcher']) and core_same(before['core'], current['core']) and
            before['hashes'] == current['hashes'] and before['mount'] == current['mount'] and
            before['startup_hashes'] == current['startup_hashes'], 'Frozen installation identity changed')


def safe_relative(path):
    require(isinstance(path, str) and not path.startswith('/') and '\\' not in path and
            all(part not in ('', '.', '..') for part in path.split('/')), 'Unsafe payload path')
    return path


def package_gate(package):
    require(re.fullmatch(re.escape(AREA) + r'/legacy-packages/legacy-[a-f0-9]{16}-[a-f0-9]{8}', package), 'Package path differs')
    directory(package)
    manifest = literal(package + '/package-manifest.py')
    require(manifest.get('schema') == 'p011.browser.legacy-package.v1', 'Package manifest differs')
    expected = manifest.get('files')
    require(isinstance(expected, dict) and {'device_install.py', 'p011_json.py', 'Z03.patched',
            'install-config.py', 'payload/BrowserPage.qml'}.issubset(expected), 'Incomplete legacy package')
    seen = set()
    for folder, directories, files in os.walk(package, followlinks=False):
        directory(folder)
        for name in directories:
            directory(folder + '/' + name)
        for name in files:
            relative = os.path.relpath(folder + '/' + name, package)
            if relative == 'package-manifest.py':
                continue
            safe_relative(relative)
            require(relative in expected, 'Unexpected legacy package member')
            info = regular(folder + '/' + name, 0o600)
            require(info.st_size == expected[relative]['bytes'] and sha(folder + '/' + name) == expected[relative]['sha256'],
                    'Legacy package integrity differs')
            seen.add(relative)
    require(seen == set(expected), 'Legacy package member set differs')
    config = literal(package + '/install-config.py')
    require(config.get('schema') == 'p011.browser.legacy-install.v1' and
            config.get('old_z03_sha256') == OLD and config.get('new_z03_sha256') == NEW and
            config.get('entry') == 'file://' + LEGACY + '/BrowserPage.qml' and
            config.get('kernel') == 'vendor-qt5' and config.get('startup_changes') is False,
            'Legacy install configuration differs')
    require(sha(package + '/Z03.patched') == NEW and
            sha(os.path.realpath(__file__)) == expected['device_install.py']['sha256'], 'Installer source binding differs')
    return config, manifest


def copy_payload(package, manifest):
    for relative in sorted(manifest['files']):
        if not relative.startswith('payload/'):
            continue
        name = safe_relative(relative[len('payload/'):])
        require(name.split('/')[0] != '_install', 'Payload overlaps installer administration')
        destination = LEGACY + '/' + name
        parent = LEGACY
        for part in name.split('/')[:-1]:
            parent += '/' + part
            if not os.path.lexists(parent):
                new_directory(parent)
            directory(parent)
        atomic(destination, read(package + '/' + relative, 16777216))
        require(sha(destination) == manifest['files'][relative]['sha256'], 'Installed QML payload readback differs')


def verify_installed(manifest):
    for relative, row in manifest['files'].items():
        if relative.startswith('payload/'):
            path = LEGACY + '/' + safe_relative(relative[len('payload/'):])
        elif relative in ('device_install.py', 'p011_json.py', 'install-config.py'):
            path = ADMIN + '/' + relative
        else:
            continue
        regular(path, 0o600)
        require(sha(path) == row['sha256'] and os.path.getsize(path) == row['bytes'], 'Installed legacy source drift')


def install(package):
    global LAST_TRANSACTION
    config, manifest = package_gate(package)
    before = live_gate(OLD)
    require(not os.path.lexists(LEGACY), 'Existing legacy installation requires inspection')
    if os.path.lexists(SETTINGS):
        directory(SETTINGS)
        require(not any(os.path.lexists(SETTINGS + '/' + name) for name in
                ('entry-config.py', 'endpoint.json', 'install-receipt.py')), 'A newer controller installation requires inspection')
    else:
        new_directory(SETTINGS)
    free = os.statvfs(AREA)
    payload_bytes = sum(row['bytes'] for key, row in manifest['files'].items() if key.startswith('payload/'))
    require(free.f_bavail * free.f_frsize >= 128 * 1024 * 1024 + 2 * os.path.getsize(TARGET) + payload_bytes,
            'Storage reserve would be violated')
    new_directory(LEGACY)
    new_directory(ADMIN)
    new_directory(ADMIN + '/backups')
    backup = ADMIN + '/backups/' + time.strftime('%Y%m%d-%H%M%S') + '-' + binascii.hexlify(os.urandom(4)).decode('ascii')
    new_directory(backup)
    LAST_TRANSACTION = backup + '/transaction.py'
    atomic(backup + '/Z03.original', read(TARGET, 16777216), before['z03_mode'], before['z03_gid'])
    require(sha(backup + '/Z03.original') == OLD, 'Current Bili Z03 backup differs')
    save(backup + '/before.py', before)
    copy_payload(package, manifest)
    for name in ('device_install.py', 'p011_json.py', 'install-config.py', 'package-manifest.py'):
        atomic(ADMIN + '/' + name, read(package + '/' + name, 16777216))
    verify_installed(manifest)
    result = {'schema': 'p011.browser.legacy-receipt.v1', 'installed': False, 'backup': backup,
              'package': package, 'config': config, 'manifest': manifest, 'before': before,
              'old_z03_sha256': OLD, 'new_z03_sha256': NEW, 'kernel': 'vendor-qt5',
              'physical_acceptance': False, 'settings_navigation_verified': False,
              'startup_changed': False, 'bili_files_changed': False}
    save(LAST_TRANSACTION, result)
    switched = False
    try:
        assert_binding(before, live_gate(OLD))
        if 'ro' in before['mount']['options']:
            remount(True)
        result['cache'] = invalidate_cache(backup, 'install')
        no_bili_session()
        switched = True  # replace can succeed before a subsequent fsync error.
        atomic(TARGET, read(package + '/Z03.patched', 16777216), before['z03_mode'], before['z03_gid'])
        require(sha(TARGET) == NEW, 'Installed legacy Z03 readback differs')
        result['ui'] = restart_ui(before['ui'], before['launcher'], OLD, NEW)
        root_mode(before['mount'])
        after = live_gate(NEW)
        require(before['boot_id'] == after['boot_id'] and same_identity(before['launcher'], after['launcher']) and
                core_same(before['core'], after['core']) and before['startup_hashes'] == after['startup_hashes'],
                'Protected process or startup identity changed')
        result['after'] = after
        result['installed'] = True
        result['root_mount_restored'] = True
        save(RECEIPT, result)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        try:
            if switched:
                require(sha(TARGET) in (OLD, NEW), 'Rollback target drift')
                if 'ro' in mounts()['options']:
                    remount(True)
                if sha(TARGET) == NEW:
                    atomic(TARGET, read(backup + '/Z03.original', 16777216), before['z03_mode'], before['z03_gid'])
                apps = [row for row in process_rows() if row['exe'] in (TARGET, TARGET + ' (deleted)')]
                require(len(apps) == 1, 'Rollback UI identity is not unique')
                running = sha('/proc/%d/exe' % apps[0]['pid'])
                require(running in (OLD, NEW), 'Rollback running UI drift')
                if running != OLD or apps[0]['exe'].endswith(' (deleted)'):
                    invalidate_cache(backup, 'rollback')
                    restart_ui(apps[0], before['launcher'], running, OLD)
            result['rolled_back'] = sha(TARGET) == OLD
        except Exception as rollback_error:
            result['rollback_error'] = type(rollback_error).__name__ + ': ' + str(rollback_error)
        raise
    finally:
        try:
            root_mode(before['mount'])
            result['root_mount_restored'] = True
        finally:
            save(LAST_TRANSACTION, result)
    return result


def receipt_gate():
    directory(ADMIN)
    receipt = literal(RECEIPT)
    require(receipt.get('schema') == 'p011.browser.legacy-receipt.v1' and receipt.get('installed') is True and
            receipt.get('old_z03_sha256') == OLD and receipt.get('new_z03_sha256') == NEW,
            'Installed legacy receipt differs')
    backup = receipt['backup']
    require(re.fullmatch(re.escape(ADMIN) + r'/backups/[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', backup), 'Backup path differs')
    directory(backup)
    regular(backup + '/Z03.original')
    require(sha(backup + '/Z03.original') == OLD, 'Original Bili Z03 backup differs')
    verify_installed(receipt['manifest'])
    return receipt


def restore():
    global LAST_TRANSACTION
    receipt = receipt_gate()
    disk_hash = sha(TARGET)
    require(disk_hash in (OLD, NEW), 'Restore target drift')
    before = live_gate(disk_hash)
    require(before['startup_hashes'] == receipt['before']['startup_hashes'], 'Startup identity changed')
    attempt = receipt['backup'] + '/restore-' + time.strftime('%Y%m%d-%H%M%S') + '-' + binascii.hexlify(os.urandom(4)).decode('ascii')
    new_directory(attempt)
    LAST_TRANSACTION = attempt + '/result.py'
    result = {'schema': 'p011.browser.legacy-restore.v1', 'restored': False,
              'backup': receipt['backup'], 'physical_acceptance': False,
              'startup_changed': False, 'bili_files_changed': False}
    try:
        assert_binding(before, live_gate(disk_hash))
        if 'ro' in before['mount']['options']:
            remount(True)
        result['cache'] = invalidate_cache(attempt, 'restore')
        if disk_hash != OLD:
            atomic(TARGET, read(receipt['backup'] + '/Z03.original', 16777216),
                   receipt['before']['z03_mode'], receipt['before']['z03_gid'])
        require(sha(TARGET) == OLD, 'Restored Bili Z03 readback differs')
        running = sha('/proc/%d/exe' % before['ui']['pid'])
        if running != OLD or before['ui']['exe'].endswith(' (deleted)'):
            result['ui'] = restart_ui(before['ui'], before['launcher'], running, OLD)
        root_mode(before['mount'])
        after = live_gate(OLD)
        require(same_identity(before['launcher'], after['launcher']) and core_same(before['core'], after['core']) and
                before['startup_hashes'] == after['startup_hashes'], 'Protected process identity changed')
        result['after'] = after
        result['restored'] = True
        save(attempt + '/retired-install-receipt.py', receipt)
        os.rename(RECEIPT, attempt + '/original-install-receipt.py')
        fsync_directory(ADMIN)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            root_mode(before['mount'])
            result['root_mount_restored'] = True
        finally:
            save(LAST_TRANSACTION, result)
    return result


def inspect():
    fingerprint = sha(TARGET)
    require(fingerprint in (OLD, NEW), 'Unknown Z03 identity')
    before = live_gate(fingerprint)
    return {'schema': 'p011.browser.legacy-inspect.v1', 'read_only': True, 'observed': before,
            'legacy_exists': os.path.lexists(LEGACY), 'receipt_exists': os.path.lexists(RECEIPT),
            'current_identity': 'installed-legacy' if fingerprint == NEW else 'prior-bili'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'install', 'restore'))
    parser.add_argument('--package')
    args = parser.parse_args()
    os.umask(0o077)
    result = {'schema': 'p011.browser.legacy-operation.v1', 'action': args.action, 'passed': False}
    lock = None
    try:
        if args.action == 'inspect':
            result['inspection'] = inspect()
        else:
            area_gate()
            lock_path = AREA + '/legacy-settings-install.lock'
            if os.path.lexists(lock_path):
                regular(lock_path, 0o600, 0)
            lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                    'Legacy installation lock differs')
            libc = ctypes.CDLL(None, use_errno=True)
            libc.flock.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.flock.restype = ctypes.c_int
            if libc.flock(lock, 6) != 0:  # LOCK_EX | LOCK_NB
                raise OSError(ctypes.get_errno(), 'Legacy installation lock failed')
            if args.action == 'install':
                require(args.package is not None, 'Explicit frozen legacy package is required')
                result['installation'] = install(args.package)
            else:
                result['restoration'] = restore()
        result['passed'] = True
        return 0
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
        return 1
    finally:
        if lock is not None:
            os.close(lock)
        if LAST_TRANSACTION:
            result['transaction_path'] = LAST_TRANSACTION
        print('RESULT=' + repr(result))
        print('REPORT_JSON=' + J.dumps(result))


if __name__ == '__main__':
    sys.exit(main())

