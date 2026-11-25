"""Fixed nine-asset validator for the one built MTA copied-factory UI.

Use the non-canonical name ui_assets in a fresh worker, before Boot is loaded.
This follows native_safety's fixed identity/exact inventory gates, but its
native-051 validator cannot authenticate this MTA bundle. No json import,
staging, credential read, process action, service or radio operation is here.
Only validate_assets(until) performs read-only device IO. Default main does not.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import time


SESSION = '2890bb25f7f13f2f735fde8a'
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
MANIFEST_PIN = (800, 'b414da2d8fd5ec1b274e286023e304036b68246c387ce4b8bd6c633d23fc4057')
PINS = (
    ('Bridge.qml', 1007, 'fe10fca184e4df629a5678f730817d35c845d1fca8cc2bffe27de4d65f7ca9e7'),
    ('FormalEntry.qml', 5348, '4913b4e996b6e31214f8be045738d3c34a309d1f25820f765e20b5ce222f3163'),
    ('Z03.mta-ui-candidate', 4103844, '16bca110706007b7f9d6a8d2e928e80ff4b586dfe32a5515d298a8a2bed96ce4'),
    ('device/MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('device/MtaHost.qml', 6205, '371f705136fb1e03aec7d283120f6915b798edd4b96cdec670f29c971d508380'),
    ('device/MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('device/MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('device/MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('device/MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
)
ROOT_NAMES = ('Bridge.qml', 'FormalEntry.qml', 'SOURCE.sha256', 'Z03.mta-ui-candidate', 'device')
DEVICE_NAMES = ('MtaButton.qml', 'MtaHost.qml', 'MtaKeyboard.qml', 'MtaLabel.qml', 'MtaPage.qml', 'MtaTheme.js')


class AssetsError(ValueError):
    def __init__(self, code, facts, rows, original=None):
        self.code, self.facts, self.rows, self.original = code, facts, rows, original
        ValueError.__init__(self, code)


def _meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def validate_assets(until):
    """Authenticate only the fixed staged files; return facts after FD closure.

    Run before creating credentials.json, or after its exact-owner removal.
    Extra files, including runtime credentials and PC build diagnostics, fail.
    A failure retains original FD rows/errors on AssetsError, never signs PASS.
    """
    rows, edges, file_rows = [], [], []
    facts = dict(session=SESSION, remote=REMOTE, assets_verified=False,
                 files_verified=0, readback_passes=0, inventory_verified=False,
                 fds_opened=0, fds_closed=0, resource_pending=True,
                 credentials_absent_verified=False, device_runtime_verified=False,
                 service_connected=False, radio_admission=False)
    original_error = None
    last = [time.monotonic()]
    deadline = None

    def need(condition, code):
        if not condition:
            raise AssetsError(code, facts, rows)

    def check():
        now = time.monotonic()
        need(math.isfinite(now) and now >= last[0] and deadline is not None and now < deadline, 'deadline')
        last[0] = now

    def open_fd(name, parent, directory=False):
        check()
        row = dict(fd=None, original_fd=None, metadata=None, closed=False,
                   unknown=True, close_called=False, close_error=None)
        rows.append(row)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        try:
            fd = os.open(name, flags, **({} if parent is None else {'dir_fd': parent}))
            row['fd'] = row['original_fd'] = fd
            need(type(fd) is int and 0 <= fd <= 0x7fffffff, 'fd_unknown')
            row['unknown'] = False
            facts['fds_opened'] += 1
            row['metadata'] = _meta(os.fstat(fd))
            check()
            return row
        except OSError as error:
            if row['fd'] is None and type(error.errno) is int and 1 <= error.errno <= 4095:
                row['unknown'] = False
                row['closed'] = True
            raise

    def directory(name, parent, policy):
        row = open_fd(name, parent, True)
        value = row['metadata']
        need(stat.S_ISDIR(value[2]) and value[5] >= 1, 'directory_type')
        if policy == 'data':
            # Sole already observed mount exception, matching original Owner.
            need(value[:5] == (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000), 'data_mount')
        else:
            mode = 0o700 if policy == 'private' else 0o755
            need(value[2:5] == (stat.S_IFDIR | mode, 0, 0), 'directory_owner_mode')
        edges.append((parent, name, row))
        return row['fd']

    def bindings_current():
        check()
        for parent, name, row in edges:
            observed = _meta(os.stat(name, follow_symlinks=False,
                                     **({} if parent is None else {'dir_fd': parent})))
            need(_meta(os.fstat(row['fd']))[:5] == row['metadata'][:5] == observed[:5], 'directory_changed')
        for parent, name, row in file_rows:
            observed = _meta(os.stat(name, dir_fd=parent, follow_symlinks=False))
            need(_meta(os.fstat(row['fd'])) == row['metadata'] == observed, 'file_changed')

    def inventory(fd):
        check()
        need(os.lseek(fd, 0, os.SEEK_SET) == 0, 'directory_offset')
        return tuple(sorted(os.listdir(fd)))

    def file(parent, name, length, digest, executable=False, manifest=False):
        bindings_current()
        row = open_fd(name, parent)
        value = row['metadata']
        mode = 0o500 if executable else 0o400
        need(value[2:7] == (stat.S_IFREG | mode, 0, 0, 1, length), 'file_owner_mode_size')
        file_rows.append((parent, name, row))
        for turn in range(2):
            check()
            need(os.lseek(row['fd'], 0, os.SEEK_SET) == 0, 'file_offset')
            hasher, count, chunks = hashlib.sha256(), 0, []
            while count < length:
                check()
                raw = os.read(row['fd'], min(65536, length - count))
                need(type(raw) is bytes and 0 < len(raw) <= min(65536, length - count), 'file_read')
                hasher.update(raw)
                count += len(raw)
                if manifest:
                    chunks.append(raw)
            need(os.read(row['fd'], 1) == b'' and hasher.hexdigest() == digest, 'file_pin')
            if manifest:
                expected = ''.join(sha + ' ' + str(size) + ' ' + path + '\n'
                                   for path, size, sha in PINS).encode('ascii')
                need(b''.join(chunks) == expected, 'manifest_bytes')
            bindings_current()
            facts['readback_passes'] += 1
        facts['files_verified'] += 1

    try:
        need(type(until) in (int, float) and math.isfinite(float(until)) and float(until) > last[0], 'deadline')
        deadline = min(float(until), last[0] + 10.0)
        need(sys.platform == 'linux' and os.geteuid() == 0 and sys.byteorder == 'little' and
             os.uname()[4] == 'armv7l' and os.O_NOFOLLOW == 0x8000 and os.O_CLOEXEC == 0x80000,
             'unsupported_platform')
        root = directory('/', None, 'public')
        mount = directory('mnt', root, 'public')
        data = directory('data', mount, 'data')
        area = directory('p011-toolbox', data, 'private')
        ui_root = directory('mta-ui', area, 'private')
        session = directory(SESSION, ui_root, 'private')
        device = directory('device', session, 'private')
        need(inventory(session) == ROOT_NAMES and
             inventory(device) == DEVICE_NAMES, 'extra_or_missing_assets')
        file(session, 'SOURCE.sha256', MANIFEST_PIN[0], MANIFEST_PIN[1], manifest=True)
        for path, length, digest in PINS:
            parent, name = (device, path[7:]) if path.startswith('device/') else (session, path)
            file(parent, name, length, digest, executable=path == 'Z03.mta-ui-candidate')
        bindings_current()
        need(inventory(session) == ROOT_NAMES and
             inventory(device) == DEVICE_NAMES, 'inventory_changed')
        facts['inventory_verified'] = True
        facts['credentials_absent_verified'] = True
        facts['assets_verified'] = facts['files_verified'] == 10 and facts['readback_passes'] == 20
    except BaseException as error:
        original_error = error
    finally:
        # Closure still runs after the validation deadline; never reopen/retry.
        for row in reversed(rows):
            fd = row['fd']
            if fd is None or row['closed']:
                continue
            row['close_called'] = True
            try:
                need(type(fd) is int and fd == row['original_fd'], 'fd_unknown')
                current = _meta(os.fstat(fd))
                need(row['metadata'] is None or current[:2] == row['metadata'][:2], 'fd_identity_changed')
                returned = os.close(fd)
                try:
                    os.fstat(fd)
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
                need(row['closed'], 'fd_close_unknown')
            except BaseException as error:
                row['close_error'] = error
                row['unknown'] = True
        facts['fds_closed'] = sum(row['fd'] is not None and row['closed'] and not row['unknown'] for row in rows)
        facts['resource_pending'] = any(not row['closed'] or row['unknown'] for row in rows)
    if original_error is not None:
        code = original_error.code if type(original_error) is AssetsError else 'asset_io'
        raise AssetsError(code, facts, rows, original_error) from None
    if facts['resource_pending'] or not facts['assets_verified']:
        raise AssetsError('asset_close', facts, rows) from None
    facts['directory_bindings'] = tuple((name, row['metadata'][:5]) for parent, name, row in edges)
    facts['file_bindings'] = tuple((name, row['metadata']) for parent, name, row in file_rows)
    return facts


if __name__ == '__main__':
    print('SOURCE_MTA_UI_ASSETS validation=false service=false credentials=false radio=false')
