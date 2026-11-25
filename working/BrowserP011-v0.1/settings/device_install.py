# -*- coding: utf-8 -*-
"""Explicit browser settings installation. Python 3.5, no vendor startup edits.

Only install/restore may temporarily remount the verified ext4 root. This is
not invoked by browser trials. All unknown files, identities and partial
transactions are retained for inspection rather than adopted or deleted.
"""
from __future__ import print_function
import argparse
import ast
import binascii
import fcntl
import hashlib
import os
import re
import signal
import stat
import subprocess
import sys
import time

import p011_json as J

AREA = '/mnt/data/p011-browser'
SETTINGS = AREA + '/settings'
TARGET = '/usr/bin/Z03'
INIT = '/etc/init.d/p011-browser-entry'
OLD = '3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896'
NEW = 'b5683da9ba99228dd458bf66bc43b7c41acf1fd4715ef4be4ae89937210c4695'
PROTECTED = {
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
FIRMWARE = 'z031_v2.4.0-20251128_174826-user'
CACHE = '/home/.cache/Z03/qmlcache'
CACHE_SOURCE = 'qrc:/ZybQmlFiles/ZybSet/SetMainPage.qml'
RECEIPT = SETTINGS + '/install-receipt.py'


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
    return [os.fsdecode(value) for value in read('/proc/%d/cmdline' % row['pid'], 65536).split(b'\0') if value]


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


def mounts():
    rows = []
    for line in read('/proc/mounts').decode('ascii').splitlines():
        values = line.split()
        if len(values) >= 4:
            rows.append({'device': values[0], 'at': values[1], 'type': values[2],
                         'options': values[3].split(',')})
    root = [row for row in rows if row['at'] == '/']
    require(len(root) == 1 and root[0]['type'] == 'ext4', 'Unsupported root mount')
    for path in (TARGET, INIT, '/etc/rc2.d', '/etc/rc3.d', '/etc/rc4.d', '/etc/rc5.d'):
        require(not any(row['at'] != '/' and
                        (path == row['at'] or path.startswith(row['at'].rstrip('/') + '/')) for row in rows),
                'Separate system mount requires review')
    return root[0]


def startup_plan():
    require(os.path.basename(os.readlink('/proc/1/exe')) in ('init', 'busybox'), 'Only verified SysV is supported')
    regular('/etc/inittab')
    text = read('/etc/inittab', 65536).decode('ascii')
    levels = re.findall(r'^\s*[^:#]+:([2-5]):initdefault:\s*$', text, re.M)
    require(len(levels) == 1, 'SysV default runlevel is not unique')
    level = levels[0]
    dispatch = re.findall(r'^\s*[^:#]+:([2-5]+):wait:(/etc/init.d/rc)\s+([2-5])\s*$', text, re.M)
    require(any(level in enabled and argument == level for enabled, path, argument in dispatch),
            'SysV runlevel dispatcher not established')
    regular('/etc/init.d/rc')
    directory('/etc/init.d')
    directory('/etc/rc' + level + '.d')
    return {'path': INIT, 'link': '/etc/rc' + level + '.d/S99p011-browser-entry',
            'link_target': '../init.d/p011-browser-entry', 'level': level,
            'inittab_sha256': sha('/etc/inittab'), 'rc_sha256': sha('/etc/init.d/rc')}


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
    protected_processes = []
    for name in ('control_engine', 'weston'):
        selected = [row for row in rows if os.path.basename(row['exe']) == name]
        require(len(selected) == 1, 'Core process identity is not unique')
        protected_processes.append(selected[0])
    require(all(row['state'] not in ('D', 'T', 't') for row in [ui, launcher] + protected_processes),
            'Core process is suspended or blocked')
    for path in ('/tmp/p011-menutest.lock', '/mnt/data/p011-menu'):
        require(not os.path.lexists(path), 'An old toolbox trial requires inspection')
    bili = None
    if check_bili:
        bili = no_bili_session()
        time.sleep(.25)
        require(no_bili_session() == bili, 'Bili state changed before installation')
    return {'boot_id': read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip(),
            'hashes': hashes, 'ui': ui, 'launcher': launcher, 'core': protected_processes,
            'mount': mounts(), 'startup': startup_plan(), 'bili_inactive': bili,
            'z03_mode': stat.S_IMODE(os.stat(TARGET).st_mode), 'z03_gid': os.stat(TARGET).st_gid}


def assert_binding(before, current):
    require(before['boot_id'] == current['boot_id'] and
            same_identity(before['ui'], current['ui']) and
            same_identity(before['launcher'], current['launcher']) and
            before['core'] == current['core'] and before['startup'] == current['startup'] and
            before['hashes'] == current['hashes'] and before['mount'] == current['mount'],
            'Frozen installation identity changed')


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


def candidate_gate(config):
    candidate = config['candidate']
    require(re.fullmatch(re.escape(AREA) + r'/candidates/browser-685-[a-f0-9]{16}', candidate), 'Candidate path differs')
    directory(candidate)
    regular(candidate + '/.candidate-complete', 0o600, 0)
    manifest = candidate + '/.candidate-manifest.py'
    require(sha(manifest) == config['manifest_literal_sha256'], 'Candidate manifest identity differs')
    stored = literal(manifest)
    require(candidate.endswith('browser-685-' + stored['sha256'][:16]), 'Candidate name is not content bound')
    expected = {}
    for row in stored['manifest']['files']:
        path = row['path']
        require(isinstance(path, str) and not path.startswith('/') and '\\' not in path and
                all(part not in ('', '.', '..') for part in path.split('/')) and path not in expected,
                'Candidate manifest path differs')
        expected[path] = row
    seen = set()
    for folder, subdirs, files in os.walk(candidate, followlinks=False):
        directory(folder)
        for name in subdirs:
            directory(folder + '/' + name)
        for name in files:
            path = folder + '/' + name
            relative = os.path.relpath(path, candidate)
            if relative in ('.candidate-manifest.py', '.candidate-complete'):
                continue
            require(relative in expected, 'Unexpected candidate file')
            row = expected[relative]
            info = regular(path, row['mode'], 1 << 31)
            require(info.st_size == row['size'] and sha(path) == row['sha256'], 'Candidate file integrity differs')
            seen.add(relative)
    require(seen == set(expected), 'Candidate member set differs')
    controller = candidate + '/runtime/entry_controller.py'
    require('runtime/entry_controller.py' in expected and sha(controller) == config['controller_sha256'],
            'Settings controller source differs')
    trial = config['trial_session']
    require(re.fullmatch(re.escape(AREA) + r'/sessions/[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', trial), 'Trial path differs')
    directory(trial)
    regular(trial + '/COMPLETE', 0o600, 0)
    require(sha(trial + '/result.py') == config['trial_result_sha256'], 'Accepted trial evidence differs')
    result = literal(trial + '/result.py')
    require(result.get('candidate') == candidate and result.get('passed') is True and
            result.get('stock_unchanged') is True and result.get('browser_exit') == 0 and
            result.get('remaining_private_processes') == [] and result.get('remaining_group') == [] and
            config.get('host_page_passed') is True, 'The browser trial has not passed')
    return {'files': len(seen), 'controller': controller}


def load_config(path):
    config = literal(path)
    require(config.get('schema') == 'p011.browser.settings-install.v1' and
            config.get('old_z03_sha256') == OLD and config.get('new_z03_sha256') == NEW and
            config.get('interactive_no_sandbox') is True, 'Settings package configuration differs')
    for name in ('manifest_literal_sha256', 'controller_sha256', 'trial_result_sha256', 'browser_entry_sha256'):
        require(isinstance(config.get(name), str) and re.fullmatch(r'[a-f0-9]{64}', config[name]), 'Configuration fingerprint differs')
    return config


def package_gate(package):
    require(re.fullmatch(re.escape(AREA) + r'/settings-packages/entry-[a-f0-9]{16}', package), 'Package path differs')
    directory(package)
    manifest = literal(package + '/package-manifest.py')
    require(manifest.get('schema') == 'p011.browser.settings-package.v1', 'Package manifest differs')
    expected = {'device_install.py', 'p011_json.py', 'BrowserEntry.qml', 'Z03.patched', 'install-config.py'}
    require(set(manifest['files']) == expected, 'Package member set differs')
    require(set(os.listdir(package)) == expected | {'package-manifest.py'}, 'Unexpected settings package member')
    for name, row in manifest['files'].items():
        regular(package + '/' + name, 0o600)
        require(os.path.getsize(package + '/' + name) == row['bytes'] and
                sha(package + '/' + name) == row['sha256'], 'Settings package integrity differs')
    config = load_config(package + '/install-config.py')
    require(sha(package + '/Z03.patched') == NEW and
            sha(package + '/BrowserEntry.qml') == config['browser_entry_sha256'] and
            sha(os.path.realpath(__file__)) == manifest['files']['device_install.py']['sha256'],
            'Settings source binding differs')
    candidate_gate(config)
    return config, manifest


def service_bytes():
    return ("#!/bin/sh\n# Independent browser settings service. Vendor scripts are untouched.\n"
            "case \"$1\" in\n"
            "start) exec /usr/bin/python3 -B /mnt/data/p011-browser/settings/device_install.py service-start ;;\n"
            "stop) exec /usr/bin/python3 -B /mnt/data/p011-browser/settings/device_install.py service-stop ;;\n"
            "status) exec /usr/bin/python3 -B /mnt/data/p011-browser/settings/device_install.py status ;;\n"
            "*) exit 2 ;;\nesac\n").encode('ascii')


def controller(config, action):
    source = config['candidate'] + '/runtime/entry_controller.py'
    regular(source, 0o644)
    require(sha(source) == config['controller_sha256'], 'Controller source differs')
    return command(['/usr/bin/python3', '-B', source, '--' + action], accepted=(0, 1))


def service_start(config):
    if controller(config, 'status') == 0:
        return {'already_running': True}
    for row in process_rows():
        require(config['candidate'] + '/runtime/entry_controller.py' not in args_of(row)[1:4],
                'An unbound controller process requires inspection')
    output = SETTINGS + '/controller-' + time.strftime('%Y%m%d-%H%M%S') + '-' + binascii.hexlify(os.urandom(4)).decode('ascii')
    with open(output + '.stdout.raw', 'xb') as stdout, open(output + '.stderr.raw', 'xb') as stderr:
        child = subprocess.Popen(['/usr/bin/python3', '-B', config['candidate'] + '/runtime/entry_controller.py'],
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 close_fds=True, start_new_session=True,
                                 env={'PATH': '/usr/bin:/bin', 'HOME': SETTINGS, 'LANG': 'C',
                                      'XDG_RUNTIME_DIR': '/run/user/0', 'WAYLAND_DISPLAY': 'wayland-0'})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError('Settings controller exited before readiness')
        if os.path.isfile(SETTINGS + '/entry-owner.py') and os.path.isfile(SETTINGS + '/endpoint.json'):
            owner = literal(SETTINGS + '/entry-owner.py')
            if owner.get('identity', {}).get('pid') == child.pid:
                require(owner.get('schema') == 'p011.browser.entry-owner.v1' and
                        owner.get('candidate') == config['candidate'] and
                        owner.get('controller_sha256') == config['controller_sha256'] and
                        owner.get('endpoint_sha256') == sha(SETTINGS + '/endpoint.json'), 'Controller owner binding differs')
                regular(SETTINGS + '/endpoint.json', 0o600, 8192)
                require(controller(config, 'status') == 0, 'Controller readiness identity differs')
                return {'already_running': False, 'owner': owner, 'stdout': output + '.stdout.raw', 'stderr': output + '.stderr.raw'}
        time.sleep(.15)
    raise RuntimeError('Settings controller readiness deadline exceeded')


def invalidate_cache(backup, phase):
    if not os.path.lexists(CACHE):
        return {'absent': True}
    directory(CACHE)
    entries = os.listdir(CACHE)
    require(len(entries) <= 2048, 'Unexpected QML cache size')
    found = []
    needles = [CACHE_SOURCE.encode('utf-8'), CACHE_SOURCE.encode('utf-16-le'), CACHE_SOURCE.encode('utf-16-be')]
    for name in entries:
        if not re.fullmatch(r'[a-f0-9]{40}\.qmlc', name):
            continue
        path = CACHE + '/' + name
        regular(path, maximum=16777216)
        body = read(path, 16777216)
        if any(needle in body for needle in needles):
            require(body.startswith(b'qv4cdata'), 'Unknown settings cache format')
            found.append((path, body, os.lstat(path)))
    require(len(found) <= 1, 'Settings cache origin is ambiguous')
    if not found:
        return {'absent': True}
    path, body, info = found[0]
    destination = backup + '/' + phase + '-SetMainPage.qmlc'
    require(not os.path.lexists(destination), 'Cache backup already exists')
    atomic(destination, body)
    fingerprint = hashlib.sha256(body).hexdigest()
    require(sha(destination) == fingerprint, 'Settings cache backup differs')
    now = os.lstat(path)
    require((now.st_dev, now.st_ino, now.st_size) == (info.st_dev, info.st_ino, info.st_size) and
            sha(path) == fingerprint, 'Settings cache changed before invalidation')
    os.unlink(path)
    fsync_directory(CACHE)
    return {'absent': False, 'path': path, 'backup': destination, 'sha256': fingerprint,
            'mode': stat.S_IMODE(info.st_mode), 'removed': True}


def checked_service(plan):
    require(startup_plan() == plan and sha(plan['path']) == hashlib.sha256(service_bytes()).hexdigest() and
            stat.S_IMODE(os.lstat(plan['path']).st_mode) == 0o755 and
            os.path.islink(plan['link']) and os.readlink(plan['link']) == plan['link_target'], 'Own service state differs')


def remove_service(plan):
    checked_service(plan)
    os.unlink(plan['link'])
    fsync_directory(os.path.dirname(plan['link']))
    os.unlink(plan['path'])
    fsync_directory(os.path.dirname(plan['path']))


def install(package):
    config, manifest = package_gate(package)
    before = live_gate(OLD)
    require(not os.path.lexists(SETTINGS), 'Existing settings state requires inspection')
    plan = before['startup']
    require(not os.path.lexists(plan['path']) and not os.path.lexists(plan['link']), 'Existing service requires inspection')
    free = os.statvfs(AREA)
    require(free.f_bavail * free.f_frsize >= 128 * 1024 * 1024 + 2 * os.path.getsize(TARGET), 'Storage reserve would be violated')
    new_directory(SETTINGS)
    new_directory(SETTINGS + '/backups')
    backup = SETTINGS + '/backups/' + time.strftime('%Y%m%d-%H%M%S') + '-' + binascii.hexlify(os.urandom(4)).decode('ascii')
    new_directory(backup)
    atomic(backup + '/Z03.original', read(TARGET, 16777216), before['z03_mode'], before['z03_gid'])
    require(sha(backup + '/Z03.original') == OLD, 'Current Bili Z03 backup differs')
    save(backup + '/before.py', before)
    for name in ('device_install.py', 'p011_json.py', 'BrowserEntry.qml', 'install-config.py', 'package-manifest.py'):
        atomic(SETTINGS + '/' + name, read(package + '/' + name, 16777216))
    entry_hashes = dict(PROTECTED)
    entry_hashes[TARGET] = NEW
    save(SETTINGS + '/entry-config.py', {'schema': 'p011.browser.entry-config.v1',
         'candidate': config['candidate'], 'manifest_literal_sha256': config['manifest_literal_sha256'],
         'hashes': entry_hashes, 'interactive_no_sandbox': True})
    result = {'schema': 'p011.browser.settings-receipt.v1', 'installed': False, 'restored': False,
              'backup': backup, 'package': package, 'candidate': config['candidate'],
              'config': config, 'manifest': manifest, 'before': before, 'startup': plan,
              'old_z03_sha256': OLD, 'new_z03_sha256': NEW,
              'physical_acceptance': False, 'settings_navigation_verified': False,
              'bili_files_changed': False, 'vendor_startup_changed': False}
    save(backup + '/transaction.py', result)
    switched = False
    service_created = False
    try:
        assert_binding(before, live_gate(OLD))
        if 'ro' in before['mount']['options']:
            remount(True)
        atomic(INIT, service_bytes(), 0o755)
        service_created = True
        os.symlink(plan['link_target'], plan['link'])
        fsync_directory(os.path.dirname(plan['link']))
        result['cache'] = invalidate_cache(backup, 'install')
        no_bili_session()
        switched = True  # os.replace may succeed even if its fsync later fails.
        atomic(TARGET, read(package + '/Z03.patched', 16777216), before['z03_mode'], before['z03_gid'])
        require(sha(TARGET) == NEW, 'Installed Z03 readback differs')
        result['ui'] = restart_ui(before['ui'], before['launcher'], OLD, NEW)
        root_mode(before['mount'])
        result['service'] = service_start(config)
        after = live_gate(NEW)
        require(before['boot_id'] == after['boot_id'] and same_identity(before['launcher'], after['launcher']) and
                before['core'] == after['core'], 'Protected process binding changed')
        checked_service(plan)
        result['after'] = after
        result['installed'] = True
        result['root_mount_restored'] = True
        save(RECEIPT, result)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        try:
            controller(config, 'stop')
            if 'ro' in mounts()['options']:
                remount(True)
            if switched:
                require(sha(TARGET) in (OLD, NEW), 'Rollback target drift')
                if sha(TARGET) == NEW:
                    atomic(TARGET, read(backup + '/Z03.original', 16777216), before['z03_mode'], before['z03_gid'])
                apps = [row for row in process_rows() if row['exe'] in (TARGET, TARGET + ' (deleted)')]
                require(len(apps) == 1, 'Rollback UI identity is not unique')
                running = sha('/proc/%d/exe' % apps[0]['pid'])
                require(running in (OLD, NEW), 'Rollback running UI drift')
                if running != OLD or apps[0]['exe'].endswith(' (deleted)'):
                    invalidate_cache(backup, 'rollback')
                    restart_ui(apps[0], before['launcher'], running, OLD)
            if service_created:
                if os.path.lexists(plan['link']):
                    require(os.path.islink(plan['link']) and os.readlink(plan['link']) == plan['link_target'], 'Rollback service link drift')
                    os.unlink(plan['link'])
                require(sha(INIT) == hashlib.sha256(service_bytes()).hexdigest(), 'Rollback service source drift')
                os.unlink(INIT)
            result['rolled_back'] = sha(TARGET) == OLD
        except Exception as rollback_error:
            result['rollback_error'] = type(rollback_error).__name__ + ': ' + str(rollback_error)
        raise
    finally:
        try:
            root_mode(before['mount'])
            result['root_mount_restored'] = True
        finally:
            save(backup + '/transaction.py', result)
    return result


def receipt_gate():
    directory(SETTINGS)
    receipt = literal(RECEIPT)
    require(receipt.get('schema') == 'p011.browser.settings-receipt.v1' and receipt.get('installed') is True and
            receipt.get('old_z03_sha256') == OLD and receipt.get('new_z03_sha256') == NEW,
            'Installed receipt differs')
    backup = receipt['backup']
    require(re.fullmatch(re.escape(SETTINGS) + r'/backups/[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', backup), 'Backup path differs')
    directory(backup)
    regular(backup + '/Z03.original')
    require(sha(backup + '/Z03.original') == OLD, 'Original Bili Z03 backup differs')
    config = load_config(SETTINGS + '/install-config.py')
    require(config == receipt['config'], 'Installed configuration drift')
    for name in ('device_install.py', 'p011_json.py', 'BrowserEntry.qml', 'install-config.py'):
        regular(SETTINGS + '/' + name, 0o600)
        require(sha(SETTINGS + '/' + name) == receipt['manifest']['files'][name]['sha256'], 'Installed entry source drift')
    return receipt, config


def restore():
    receipt, config = receipt_gate()
    before = live_gate(NEW)
    checked_service(receipt['startup'])
    require(before['startup'] == receipt['startup'], 'Installed SysV binding changed')
    result = {'schema': 'p011.browser.settings-restore.v1', 'restored': False, 'backup': receipt['backup'],
              'physical_acceptance': False, 'bili_files_changed': False}
    try:
        require(controller(config, 'stop') == 0, 'Own controller stop was not confirmed')
        no_bili_session()
        if 'ro' in before['mount']['options']:
            remount(True)
        result['cache'] = invalidate_cache(receipt['backup'], 'restore')
        atomic(TARGET, read(receipt['backup'] + '/Z03.original', 16777216),
               receipt['before']['z03_mode'], receipt['before']['z03_gid'])
        require(sha(TARGET) == OLD, 'Restored Bili Z03 readback differs')
        result['ui'] = restart_ui(before['ui'], before['launcher'], NEW, OLD)
        remove_service(receipt['startup'])
        root_mode(before['mount'])
        result['after'] = live_gate(OLD)
        require(same_identity(before['launcher'], result['after']['launcher']) and
                before['core'] == result['after']['core'], 'Protected process identity changed')
        result['restored'] = True
        save(receipt['backup'] + '/restored-install-receipt.py', receipt)
        os.rename(RECEIPT, receipt['backup'] + '/retired-install-receipt.py')
        fsync_directory(SETTINGS)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
        # If the browser-menu Z03 still exists, recover only its exact service.
        try:
            if sha(TARGET) == NEW:
                root_mode(before['mount'])
                result['service_recovered'] = service_start(config)
        except Exception as recovery_error:
            result['recovery_error'] = type(recovery_error).__name__ + ': ' + str(recovery_error)
        raise
    finally:
        try:
            root_mode(before['mount'])
            result['root_mount_restored'] = True
        finally:
            save(receipt['backup'] + '/restore-result.py', result)
    return result


def inspect():
    fingerprint = sha(TARGET)
    require(fingerprint in (OLD, NEW), 'Unknown Z03 identity')
    before = live_gate(fingerprint)
    return {'schema': 'p011.browser.settings-inspect.v1', 'read_only': True, 'observed': before,
            'settings_exists': os.path.lexists(SETTINGS), 'receipt_exists': os.path.lexists(RECEIPT),
            'service_exists': os.path.lexists(INIT)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'install', 'restore', 'service-start', 'service-stop', 'status'))
    parser.add_argument('--package')
    args = parser.parse_args()
    os.umask(0o077)
    result = {'schema': 'p011.browser.settings-operation.v1', 'action': args.action, 'passed': False}
    lock = None
    try:
        if args.action in ('service-start', 'service-stop', 'status'):
            require(os.geteuid() == 0, 'Root service control required')
            config = load_config(SETTINGS + '/install-config.py')
            if args.action == 'service-start':
                result['service'] = service_start(config)
            else:
                code = controller(config, 'stop' if args.action == 'service-stop' else 'status')
                require(code == 0, 'Own service state was not confirmed')
        elif args.action == 'inspect':
            result['inspection'] = inspect()
        else:
            area_gate()
            lock_path = AREA + '/settings-install.lock'
            if os.path.lexists(lock_path):
                regular(lock_path, 0o600, 0)
            lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                    'Installation lock differs')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'install':
                require(args.package is not None, 'Explicit frozen package is required')
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
        print('RESULT=' + repr(result))
        print('REPORT_JSON=' + J.dumps(result))


if __name__ == '__main__':
    sys.exit(main())
