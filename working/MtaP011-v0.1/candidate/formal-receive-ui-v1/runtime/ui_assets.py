"""Fixed nine-payload/ten-file validator for the built Receive UI-v1.

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


SESSION = '2c3d526c2d034da16e6c4a61'
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
MANIFEST_PIN = (782, 'f6825699bd8fd769bc6330754def7dda16effed4ec211e0e636e9166f50b3d53')
PINS = (
    ('Bridge.qml', 2560, '11f7d35b459069b78c6c43d97e525c9696086654f5e64cce4d9a6088c233f216'),
    ('FormalEntry.qml', 3555, 'b55235dcd9e0d3e663b2591ec451e0745af6bcf9a52222bb4ff978ed6ce14a6d'),
    ('Z03.mta-ui-candidate', 4103844, '5a223ec9244a5e5b701ecea4e908f6f8c6d62bffe395f19abd5493a184efa8af'),
    ('mta/MtaButton.qml', 758, '7e1d4e378b8e3293e617f4dc432cce3c70ae7fe377f2ea26950aa9bb11393bff'),
    ('mta/MtaHost.qml', 6492, '665228a27b4cdb3d0ff65e634102ac6a6b92616a1eaf109e311022a8b33138b9'),
    ('mta/MtaKeyboard.qml', 5345, '2de31e8cde68ab6ff76f4da85c386d5cddb466cccefb809987dddfce2f8c40cc'),
    ('mta/MtaLabel.qml', 352, '77caf248c2f83ed50f5221082084e5af360d08fc917df98eb84449e24903bd75'),
    ('mta/MtaPage.qml', 27785, 'f670c134d91011ef643f3d5bbff9583552eada65482a80a41b8d0e76e0563cd8'),
    ('mta/MtaTheme.js', 262, '5848aa8bf1dab57cfe590dd80da1122eb819c75c1f208f69ad4184bf669a99ff'),
)
ROOT_NAMES = ('Bridge.qml', 'FormalEntry.qml', 'SOURCE.sha256', 'Z03.mta-ui-candidate', 'mta')
MTA_NAMES = ('MtaButton.qml', 'MtaHost.qml', 'MtaKeyboard.qml', 'MtaLabel.qml', 'MtaPage.qml', 'MtaTheme.js')


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
        mta = directory('mta', session, 'private')
        need(inventory(session) == ROOT_NAMES and
             inventory(mta) == MTA_NAMES, 'extra_or_missing_assets')
        file(session, 'SOURCE.sha256', MANIFEST_PIN[0], MANIFEST_PIN[1], manifest=True)
        for path, length, digest in PINS:
            parent, name = (mta, path[4:]) if path.startswith('mta/') else (session, path)
            file(parent, name, length, digest, executable=path == 'Z03.mta-ui-candidate')
        bindings_current()
        need(inventory(session) == ROOT_NAMES and
             inventory(mta) == MTA_NAMES, 'inventory_changed')
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
    print('SOURCE_RECEIVE_UI_V1_ASSETS validation=false service=false credentials=false radio=false')
