"""Fixed 19-file validator for the built FileCenter and MTA copied-factory UI.

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


SESSION = 'b6a84fe755092535bb996f40'
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
MANIFEST_PIN = (1603, 'b334d5ebc0598ca0583406efed9c063894e30c97186e12b28846545a8600ad24')
PINS = (
    ('Bridge.qml', 1007, '73454ae237dcfc75cac8f82045bde9fbf24339797ece9def1dc7b972cc0c96ae'),
    ('FormalEntry.qml', 4079, '2310e99d70e53903e390598a82f9d2c46ae03c1621bc0fa4505c39349830cb3d'),
    ('ReceiveComposition.qml', 401, '6f1701b31faa62822dcf3e51afd74e001c000d588c6df1cba8b6700e8320ac39'),
    ('Z03.mta-ui-candidate', 4103844, '6e8d5aab7a9c0af6e83ba2d4eb09c37054f175de294169c099357f300aef985c'),
    ('mta/MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('mta/MtaHost.qml', 6341, 'e610b343fe4058bb89d45ee65cb14bdd4471363b56a737d85ab5c51297e42f11'),
    ('mta/MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('mta/MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('mta/MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('mta/MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
    ('toolbox/Button.qml', 665, 'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('toolbox/ExtensionPage.qml', 10109, 'e2ea4ac96acda29509df272001599be9410d5989a2400bfaef73901378062093'),
    ('toolbox/FilesPage.qml', 11639, '5f1b4255211f4369f64dfc24eddcc565d6e6a64f708e181e15b68828376bd1e1'),
    ('toolbox/Label.qml', 269, '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    ('toolbox/MtaEmbedded.qml', 6543, 'cf5e0c34eae957e8f6ebd5c0641ff7d6d177cb8407db3957049255e6e94e095b'),
    ('toolbox/NativeIcon.qml', 1999, '08baa5b5b7176fc5abaa59c5ef261f0474c05565838a68fa6c110aed80867f4d'),
    ('toolbox/Theme.js', 244, '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
    ('toolbox/VideoPane.qml', 705, 'e09873e298aa6b762051ab866ca82ea5b44f0d2988ab97e6ad6719c947934651'),
)
ROOT_NAMES = ('Bridge.qml', 'FormalEntry.qml', 'ReceiveComposition.qml', 'SOURCE.sha256',
              'Z03.mta-ui-candidate', 'mta', 'toolbox')
MTA_NAMES = ('MtaButton.qml', 'MtaHost.qml', 'MtaKeyboard.qml', 'MtaLabel.qml', 'MtaPage.qml', 'MtaTheme.js')
TOOLBOX_NAMES = ('Button.qml', 'ExtensionPage.qml', 'FilesPage.qml', 'Label.qml',
                 'MtaEmbedded.qml', 'NativeIcon.qml', 'Theme.js', 'VideoPane.qml')


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
    rows, edges, file_rows, relative_file_rows = [], [], [], []
    credential_edges = ()
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

    def file(parent, name, length, digest, executable=False, manifest=False, relative_path=None):
        bindings_current()
        row = open_fd(name, parent)
        value = row['metadata']
        mode = 0o500 if executable else 0o400
        need(value[2:7] == (stat.S_IFREG | mode, 0, 0, 1, length), 'file_owner_mode_size')
        file_rows.append((parent, name, row))
        relative_file_rows.append((name if relative_path is None else relative_path, row))
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
        # Credential checks follow only the original chain, never sibling dirs.
        credential_edges = tuple(edges)
        mta = directory('mta', session, 'private')
        toolbox = directory('toolbox', session, 'private')
        need(inventory(session) == ROOT_NAMES and
             inventory(mta) == MTA_NAMES and
             inventory(toolbox) == TOOLBOX_NAMES, 'extra_or_missing_assets')
        file(session, 'SOURCE.sha256', MANIFEST_PIN[0], MANIFEST_PIN[1], manifest=True)
        for path, length, digest in PINS:
            if path.startswith('mta/'):
                parent, name = mta, path[4:]
            elif path.startswith('toolbox/'):
                parent, name = toolbox, path[8:]
            else:
                parent, name = session, path
            need('/' not in name and name not in ('', '.', '..'), 'asset_path')
            file(parent, name, length, digest, executable=path == 'Z03.mta-ui-candidate',
                 relative_path=path)
        bindings_current()
        need(inventory(session) == ROOT_NAMES and
             inventory(mta) == MTA_NAMES and
             inventory(toolbox) == TOOLBOX_NAMES, 'inventory_changed')
        facts['inventory_verified'] = True
        facts['credentials_absent_verified'] = True
        facts['assets_verified'] = facts['files_verified'] == 19 and facts['readback_passes'] == 38
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
    facts['credential_directory_bindings'] = tuple((name, row['metadata'][:5])
                                                  for parent, name, row in credential_edges)
    facts['file_bindings'] = tuple((path, row['metadata']) for path, row in relative_file_rows)
    return facts


if __name__ == '__main__':
    print('SOURCE_RECEIVE_FILECENTER_UI_ASSETS validation=false service=false credentials=false radio=false')


