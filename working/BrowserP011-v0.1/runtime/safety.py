# -*- coding: utf-8 -*-
"""Python 3.5 safety boundaries for an isolated P011 browser trial.

No account data, environment values or command lines are collected. This file
does not signal vendor processes or alter system configuration.
"""
import ast
import hashlib
import os
import re
import signal
import stat
import time

AREA = '/mnt/data/p011-browser'
HASH_PATHS = ('/usr/bin/Z03', '/usr/bin/control_engine', '/usr/bin/zyb_z03_launch.sh')
CORE_NAMES = ('Z03', 'control_engine', 'weston')
OBSERVED_NAMES = CORE_NAMES + ('connmand', 'bluetoothd')
SCHEMAS = ('p011.browser.baseline.v1', 'p011.browser.readonly.v1')


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def identity(pid):
    with open('/proc/' + str(int(pid)) + '/stat') as handle:
        raw = handle.read(8192)
    end = raw.rindex(')')
    fields = raw[end + 2:].split()
    return {'pid': int(pid), 'name': raw[raw.index('(') + 1:end],
            'parent': int(fields[1]), 'group': int(fields[2]),
            'session': int(fields[3]), 'starttime': fields[19],
            'exe': os.readlink('/proc/' + str(int(pid)) + '/exe')}


def _positive_int(value, label, zero=False):
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if zero else 1):
        raise ValueError('Invalid ' + label)
    return value


def canonical_identity(row):
    if not isinstance(row, dict):
        raise ValueError('Process identity must be a dictionary')
    pid = _positive_int(row.get('pid'), 'pid')
    name = row.get('name', row.get('comm'))
    parent = row.get('parent')
    parent_pid = row.get('ppid') if isinstance(parent, dict) or parent is None else parent
    parent_pid = _positive_int(parent_pid, 'parent pid', True)
    start = row.get('starttime')
    if isinstance(start, bool) or not isinstance(start, (int, str)) or not re.fullmatch(r'[0-9]+', str(start)):
        raise ValueError('Invalid process starttime')
    exe = row.get('exe')
    if not isinstance(name, str) or not name or len(name) > 64 or '\x00' in name:
        raise ValueError('Invalid process name')
    if not isinstance(exe, str) or not exe.startswith('/') or len(exe) > 4096 or '\x00' in exe:
        raise ValueError('Invalid process executable')
    return {'pid': pid, 'name': name, 'parent': parent_pid,
            'starttime': str(start), 'exe': exe}


def normalize_snapshot(value):
    if not isinstance(value, dict) or value.get('schema') not in SCHEMAS:
        raise ValueError('Unsupported baseline schema')
    hashes = value.get('hashes')
    if not isinstance(hashes, dict) or set(hashes) != set(HASH_PATHS):
        raise ValueError('Baseline requires the exact three stock hashes')
    for checksum in hashes.values():
        if not isinstance(checksum, str) or not re.fullmatch(r'[a-f0-9]{64}', checksum):
            raise ValueError('Invalid stock checksum')
    rows = value.get('processes')
    if not isinstance(rows, list) or not 3 <= len(rows) <= 64:
        raise ValueError('Invalid baseline processes')
    observed = []
    for source in rows:
        row = canonical_identity(source)
        if row['name'] not in OBSERVED_NAMES:
            continue
        if row['name'] in ('Z03', 'control_engine'):
            if row['exe'] != '/usr/bin/' + row['name']:
                raise ValueError('Stock executable is redirected')
            parent = source.get('parent_identity')
            if parent is None and isinstance(source.get('parent'), dict):
                parent = source['parent']
            row['parent_identity'] = canonical_identity(parent)
            if row['parent_identity']['pid'] != row['parent']:
                raise ValueError('Stock parent identity differs')
        observed.append(row)
    if len(set(r['pid'] for r in observed)) != len(observed):
        raise ValueError('Duplicate stock process')
    for name in CORE_NAMES:
        if len([r for r in observed if r['name'] == name]) != 1:
            raise ValueError('Expected one stock ' + name)
    result = {'schema': SCHEMAS[0], 'hashes': dict(hashes),
              'processes': sorted(observed, key=lambda row: row['pid'])}
    boot_id = value.get('boot_id')
    if boot_id is not None:
        if not isinstance(boot_id, str) or not re.fullmatch(r'[a-f0-9-]{36}', boot_id):
            raise ValueError('Invalid boot identity')
        result['boot_id'] = boot_id
    return result


def stock_snapshot():
    rows = []
    for item in os.listdir('/proc'):
        if not item.isdigit():
            continue
        try:
            row = identity(int(item))
            if row['name'] in OBSERVED_NAMES:
                if row['name'] in ('Z03', 'control_engine'):
                    row['parent_identity'] = identity(row['parent'])
                rows.append(row)
        except (OSError, ValueError, IndexError):
            continue
    with open('/proc/sys/kernel/random/boot_id') as handle:
        boot_id = handle.read(64).strip()
    return normalize_snapshot({'schema': SCHEMAS[0],
                               'hashes': {path: digest(path) for path in HASH_PATHS},
                               'processes': rows, 'boot_id': boot_id})


def same_stock(before, after):
    left, right = normalize_snapshot(before), normalize_snapshot(after)
    if 'boot_id' not in left:
        right.pop('boot_id', None)
    return left == right


def owned_directory(path):
    if not isinstance(path, str) or not path.startswith(AREA + '/') or os.path.normpath(path) != path:
        raise ValueError('Outside the private browser area')
    current = ''
    for part in path.strip('/').split('/'):
        current += '/' + part
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError('Missing or redirected browser directory')
    if os.path.realpath(path) != path:
        raise ValueError('Redirected browser path')
    return path


def control_directory(path):
    owned_directory(path)
    current = AREA
    for part in [''] + path[len(AREA):].strip('/').split('/'):
        if part:
            current += '/' + part
        info = os.stat(current)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Browser control directory is writable by another owner')
    return path


def validate_paths(candidate, session):
    if not re.fullmatch(re.escape(AREA) + r'/candidates/browser-685-[a-f0-9]{16,64}', candidate):
        raise ValueError('Unexpected browser candidate')
    if not re.fullmatch(re.escape(AREA) + r'/sessions/[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', session):
        raise ValueError('Unexpected browser session')
    control_directory(candidate)
    control_directory(session)
    marker = AREA + '/.area-owner'
    info = os.lstat(marker)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('Private browser area marker differs')
    descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if os.read(descriptor, 128) != b'p011.browser.area.v1\n':
            raise ValueError('Private browser area marker differs')
    finally:
        os.close(descriptor)
    return candidate, session


def read_literal(path, maximum=131072):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Unsafe control file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Control file changed while opening')
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            fd = None
            raw = handle.read(maximum + 1)
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > maximum:
        raise ValueError('Control file exceeds limit')
    return ast.literal_eval(raw)


def load_baseline(path, session):
    if os.path.dirname(path) != session or os.path.normpath(path) != path:
        raise ValueError('Baseline must be a direct session control file')
    return normalize_snapshot(read_literal(path))


def write_new(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def stop_requested(session):
    path = session + '/STOP'
    try:
        info = os.lstat(path)
    except OSError as exc:
        if exc.errno == 2:
            return False
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size != 0:
        raise ValueError('Unsafe STOP request')
    return True


PUBLIC_SITES = ('baidu', 'bilibili')


def trial_mode(offline_no_sandbox=False, public_site=None, public_no_sandbox=False,
               interactive=False, interactive_no_sandbox=False):
    """Validate explicit trial scope without creating a general URL interface."""
    if public_site is not None and public_site not in PUBLIC_SITES:
        raise ValueError('Unsupported public site')
    if (public_site is not None) != bool(public_no_sandbox):
        raise ValueError('Public site and public no-sandbox must be supplied together')
    if offline_no_sandbox and public_site is not None:
        raise ValueError('Offline and public trials are mutually exclusive')
    if bool(interactive) != bool(interactive_no_sandbox):
        raise ValueError('Interactive browser and interactive no-sandbox must be supplied together')
    if interactive and (offline_no_sandbox or public_site is not None):
        raise ValueError('Interactive and page-probe modes are mutually exclusive')
    return {'public_site': public_site, 'public_no_sandbox': bool(public_no_sandbox),
            'interactive': bool(interactive), 'interactive_no_sandbox': bool(interactive_no_sandbox),
            'sandbox_enabled': not (offline_no_sandbox or public_no_sandbox or interactive_no_sandbox),
            'sandbox_runtime_verified': False,
            'offline_local_fixture_only': public_site is None and not interactive}


def browser_environment(candidate, session, wayland_fd, shell_integration, offline_no_sandbox=False,
                        public_site=None, public_no_sandbox=False,
                        interactive=False, interactive_no_sandbox=False):
    mode = trial_mode(offline_no_sandbox, public_site, public_no_sandbox,
                      interactive, interactive_no_sandbox)
    # A fresh allowlist prevents inherited Chromium flags (including no-sandbox),
    # arbitrary Qt plugin paths or account environment from entering the trial.
    app = session + '/app'
    env = {'PATH': '/usr/bin:/bin', 'HOME': app, 'LANG': 'C.UTF-8',
            'TMPDIR': app + '/tmp', 'XDG_CACHE_HOME': app + '/cache',
            'XDG_CONFIG_HOME': app + '/config', 'XDG_DATA_HOME': app + '/data',
            'XDG_RUNTIME_DIR': app + '/runtime', 'WAYLAND_SOCKET': str(wayland_fd),
            'QT_QPA_PLATFORM': 'wayland', 'QT_WAYLAND_SHELL_INTEGRATION': shell_integration,
            'QT_QUICK_CONTROLS_STYLE': 'Basic', 'QML_DISABLE_DISK_CACHE': '1',
            'PYTHONDONTWRITEBYTECODE': '1', 'LD_LIBRARY_PATH': candidate + '/lib',
            'QT_PLUGIN_PATH': candidate + '/plugins', 'QML2_IMPORT_PATH': candidate + '/qml',
            'QML_IMPORT_PATH': candidate + '/qml',
            'QTWEBENGINEPROCESS_PATH': candidate + '/libexec/QtWebEngineProcess',
            'QTWEBENGINE_RESOURCES_PATH': candidate + '/resources',
            'QTWEBENGINE_LOCALES_PATH': candidate + '/translations/qtwebengine_locales',
            'QTWEBENGINE_CHROMIUM_FLAGS': ('--disable-background-networking '
                '--disable-component-update --disable-sync --disable-domain-reliability '
                '--disable-default-apps --metrics-recording-only --no-first-run '
                '--no-default-browser-check --disable-breakpad')}
    if not mode['sandbox_enabled']:
        # Each no-sandbox scope requires an explicit option. Public mode also
        # requires a fixed site label; startup failure never changes modes.
        env['QTWEBENGINE_DISABLE_SANDBOX'] = '1'
    return env


def validate_child_user(uid, gid):
    _positive_int(uid, 'browser uid')
    _positive_int(gid, 'browser gid')
    if os.geteuid() != 0 and (uid != os.geteuid() or gid != os.getegid()):
        raise ValueError('Cannot change child credentials')
    return uid, gid


def validate_app_directory(session, uid, gid):
    app = owned_directory(session + '/app')
    for path in (app,) + tuple(app + '/' + part for part in ('tmp', 'cache', 'config', 'data', 'runtime')):
        owned_directory(path)
        info = os.stat(path)
        if info.st_uid != uid or info.st_gid != gid or info.st_mode & 0o077:
            raise ValueError('Application directory must be private to browser uid/gid')
    return app


def group_members(leader):
    members = []
    for item in os.listdir('/proc'):
        if not item.isdigit():
            continue
        try:
            row = identity(int(item))
            if row['group'] == leader['pid'] and row['session'] == leader['pid']:
                members.append(row)
        except (OSError, ValueError, IndexError):
            continue
    return sorted(members, key=lambda row: row['pid'])


def checked_group(candidate, leader):
    if leader.get('group') != leader.get('pid') or leader.get('session') != leader.get('pid'):
        raise ValueError('Browser was not started in its own session/group')
    try:
        current = identity(leader['pid'])
    except OSError as exc:
        if exc.errno not in (2, 3):
            raise
        current = None
    stable = lambda row: tuple(row[key] for key in ('pid', 'starttime', 'exe', 'group', 'session'))
    if current is not None and stable(current) != stable(leader):
        raise ValueError('Browser leader identity changed; refusing a signal')
    members = group_members(leader)
    allowed = (candidate + '/bin/p011-browser-probe', candidate + '/libexec/QtWebEngineProcess')
    for row in members:
        if row['exe'] not in allowed or row['group'] != leader['pid'] or row['session'] != leader['pid']:
            raise ValueError('Unexpected process in browser group; refusing a signal')
    return members


def signal_owned_group(candidate, leader, signum):
    members = checked_group(candidate, leader)
    if not members:
        return []
    # Recheck every PID immediately before the group signal, including starttime.
    for row in members:
        try:
            current = identity(row['pid'])
        except OSError as exc:
            if exc.errno in (2, 3):
                continue
            raise
        if tuple(current[key] for key in ('pid', 'starttime', 'exe', 'group', 'session')) != tuple(row[key] for key in ('pid', 'starttime', 'exe', 'group', 'session')):
            raise ValueError('Browser member identity changed; refusing a signal')
    try:
        os.killpg(leader['pid'], signum)
    except OSError as exc:
        if exc.errno != 3:
            raise
    return [canonical_identity(row) for row in members]


def private_processes(candidate):
    # Only exe links are inspected. No /proc/*/cmdline or environment is read.
    result = []
    for item in os.listdir('/proc'):
        if not item.isdigit():
            continue
        try:
            row = identity(int(item))
            if row['exe'].startswith(candidate + '/'):
                result.append(row)
        except (OSError, ValueError, IndexError):
            continue
    return sorted(result, key=lambda row: row['pid'])


def acquire_lease(candidate, session):
    base = AREA + '/leases'
    control_directory(AREA)
    try:
        os.mkdir(base, 0o700)
    except OSError as exc:
        if exc.errno != 17:
            raise
    control_directory(base)
    lease = base + '/' + os.path.basename(candidate)
    os.mkdir(lease, 0o700)  # An existing/stale lease is never removed automatically.
    owner = {'session': session, 'owner': canonical_identity(identity(os.getpid()))}
    write_new(lease + '/owner.py', repr(owner) + '\n')
    return lease, owner


def release_lease(lease, owner):
    control_directory(lease)
    if read_literal(lease + '/owner.py') != owner:
        raise ValueError('Candidate lease owner changed')
    os.unlink(lease + '/owner.py')
    os.rmdir(lease)


def track_descendants(candidate, leader, tracked, uid):
    rows = private_processes(candidate)
    allowed = (candidate + '/bin/p011-browser-probe', candidate + '/libexec/QtWebEngineProcess')
    for unused in range(4):
        changed = False
        for row in rows:
            key = (row['pid'], row['starttime'], row['exe'])
            if key in tracked or row['exe'] not in allowed:
                continue
            try:
                owner_uid = os.stat('/proc/' + str(row['pid'])).st_uid
            except OSError as exc:
                if exc.errno in (2, 3):
                    continue
                raise
            if owner_uid != uid:
                continue
            linked = (row['pid'] == leader['pid'] and row['starttime'] == leader['starttime'] or
                      row['group'] == leader['pid'] and row['session'] == leader['pid'])
            if not linked:
                for known in list(tracked.values()):
                    if row['parent'] == known['pid']:
                        try:
                            parent = identity(known['pid'])
                        except OSError:
                            continue
                        if parent['starttime'] == known['starttime'] and parent['exe'] == known['exe']:
                            linked = True
                            break
            if linked:
                tracked[key] = row
                changed = True
        if not changed:
            break
    return rows


def signal_owned_pid(candidate, expected, uid, signum):
    allowed = (candidate + '/bin/p011-browser-probe', candidate + '/libexec/QtWebEngineProcess')
    if expected.get('exe') not in allowed:
        raise ValueError('PID executable is not a browser component')
    try:
        current = identity(expected['pid'])
        owner = os.stat('/proc/' + str(expected['pid'])).st_uid
    except OSError as exc:
        if exc.errno in (2, 3):
            return None
        raise
    # Parent/group/session can change for a Chromium child after fork/setsid.
    # PID/starttime/exe and uid are the immutable ownership checks here.
    if (current['pid'], current['starttime'], current['exe'], owner) != (expected['pid'], expected['starttime'], expected['exe'], uid):
        raise ValueError('Browser PID identity changed; refusing a signal')
    try:
        os.kill(current['pid'], signum)
    except OSError as exc:
        if exc.errno != 3:
            raise
    return canonical_identity(current)
