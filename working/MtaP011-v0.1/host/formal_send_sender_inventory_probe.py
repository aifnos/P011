"""Fixed P011 readonly inventory SOURCE; ROOT alone executes on the device.

Lists only sender asset root immediate names/types and no file contents.
RESULT names/metadata are private, not a public archive. This is
current inventory evidence, NOT the historical StageError.code or a stage run.
No mkdir, writes, permission change, move/delete, helper, Boot, Owner or RF.
"""
import errno
import os
import signal
import stat
import sys


TOP = ('native', 'runtime', 'source-manifest.json')


def meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def check(value):
    if not value:
        raise ValueError('inventory_unknown')


def run():
    check(sys.platform == 'linux' and os.geteuid() == 0 and os.uname()[4] == 'armv7l')
    check(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and
          signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
    signal.alarm(20)
    rows, edges, aliases = [], [], []
    failure = None
    result = None

    def current():
        for path, original, target in aliases:
            check(meta(os.lstat(path)) == original and os.readlink(path) == target)
        for parent, name, row in edges:
            check(meta(os.fstat(row['fd']))[:5] == row['metadata'][:5] and
                  meta(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == row['metadata'][:5])

    def directory(parent, name, mode):
        current()
        before = meta(os.stat(name, dir_fd=parent, follow_symlinks=False))
        check(before[2] == stat.S_IFDIR | mode and before[3:5] == (0, 0))
        row = dict(fd=None, metadata=before, known=False, returned=False, closing=False, closed=False)
        rows.append(row)
        try:
            row['fd'] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            row['returned'] = True
            check(type(row['fd']) is int and row['fd'] > 2 and meta(os.fstat(row['fd'])) == before)
            row['known'] = True
        except OSError:
            if not row['returned']:
                row['known'] = row['closed'] = True
            raise
        edges.append((parent, name, row))
        current()
        return row

    def snapshot(row):
        current()
        before = meta(os.fstat(row['fd']))
        check(os.lseek(row['fd'], 0, os.SEEK_SET) == 0)
        names = os.listdir(row['fd'])
        check(type(names) is list and len(names) <= 4096 and all(type(name) is str for name in names))
        entries = []
        for name in sorted(names):
            value = meta(os.stat(name, dir_fd=row['fd'], follow_symlinks=False))
            kind = ('directory' if stat.S_ISDIR(value[2]) else 'file' if stat.S_ISREG(value[2]) else
                    'symlink' if stat.S_ISLNK(value[2]) else 'other')
            entries.append((name, kind, value))
        check(meta(os.fstat(row['fd'])) == before)
        current()
        return (tuple(sorted(names)), tuple(entries), before)

    try:
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            observed = meta(os.lstat(path))
            check(observed[2] == stat.S_IFLNK | 0o777 and observed[3:6] == (0, 0, 1) and
                  observed[6] == len(target) and os.readlink(path) == target)
            aliases.append((path, observed, target))
        parent = directory(None, '/', 0o755)
        for name, mode in (('var', 0o755), ('volatile', 0o1777), ('tmp', 0o1777),
                           ('p011-mta-go-send-v76-assets', 0o700)):
            parent = directory(parent['fd'], name, mode)
        first = snapshot(parent)
        # Top-level observation only. Never descend even a known child name.
        second = snapshot(parent)
        check(first == second)
        result = dict(expected_top=TOP, actual_top=first[0], actual_top_count=len(first[0]),
                      top_entries=first[1], top_exact=first[0] == TOP, two_snapshots_stable=True,
                      file_contents_read=False, writes=False)
    except BaseException as error:
        failure = error
    finally:
        for row in reversed(rows):
            if row['closed'] or not row['known'] or not row['returned'] or row['closing']:
                continue
            row['closing'] = True
            try:
                check(meta(os.fstat(row['fd']))[:5] == row['metadata'][:5])
                check(os.close(row['fd']) is None)
                try:
                    os.fstat(row['fd'])
                except OSError as error:
                    check(error.errno == errno.EBADF)
                    row['closed'] = True
                else:
                    check(False)
            except BaseException as error:
                if failure is None:
                    failure = error
        closed = all(row['known'] and row['closed'] for row in rows)
        if closed:
            signal.alarm(0)
        if result is not None:
            result.update(resources_closed=closed, original_fds=sum(row['returned'] for row in rows),
                          original_fds_closed=sum(row['returned'] and row['closed'] for row in rows))
            print('RESULT=' + repr(result))
        if failure is not None:
            raise failure
        check(closed and result is not None)


# HOST_ENTRY
def host_main():
    """Thin Windows launcher; default is PC-only, raw names stay private."""
    import argparse
    import ast
    import base64
    import datetime
    import hashlib
    import importlib.util
    import json
    from pathlib import Path
    import re
    import uuid
    import zlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    base = Path(__file__).resolve().parents[1]
    original = Path(__file__).read_bytes()
    text = original.decode('utf-8').replace('\r\n', '\n')
    marker = '\n# HOST_ENTRY\n'
    if text.count(marker) != 1:
        raise ValueError('source_shape')
    source = text.split(marker, 1)[0] + "\nif __name__ == '__main__':\n    run()\n"
    payload = base64.b64encode(zlib.compress(source.encode('utf-8'))).decode('ascii')
    # Identical to the pinned Adb.python compressed command; prohibit its fallback.
    command = ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
               payload + '\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    if len(command) > 3500 or max(map(len, source.splitlines())) > 2048:
        raise ValueError('transport_source_budget')
    transport_path = base / 'host/device_probe.py'
    transport = transport_path.read_bytes()
    if (len(transport) != 8759 or hashlib.sha256(transport).hexdigest() !=
            'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'):
        raise ValueError('transport_source_identity')
    directory = base / 'results' / ('sender-top-inventory-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    directory.mkdir(parents=False, exist_ok=False)
    private = directory / 'private-raw'
    private.mkdir()
    (private / 'launcher.source.py').write_bytes(original)
    (private / 'target.source.py').write_bytes(source.encode('utf-8'))
    (private / 'transport.source.py').write_bytes(transport)
    public = dict(device_invoked=False, command_characters=len(command),
                  top_exact=None, two_snapshots_stable=None, actual_top_count=None,
                  type_counts=None, resources_closed=None, original_fds=None,
                  original_fds_closed=None, remote_exit=None, host_exit=None,
                  error_kind=None)
    if not args.check_device:
        (directory / 'result.json').write_text(json.dumps(public, indent=2), encoding='utf-8')
        print(json.dumps(public, sort_keys=True))
        print('RESULT_DIR=' + str(directory))
        return 0
    result, failure = None, None
    try:
        spec = importlib.util.spec_from_file_location('_fixed_sender_inventory_transport', transport_path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(transport, str(transport_path), 'exec'), module.__dict__)
        if Path(module.ADB).resolve() != Path('C:/Program Files/ADB/adb.exe').resolve():
            raise ValueError('transport_executable')
        adb = module.Adb(private)
        public['device_invoked'] = True
        result = adb.python('sender-top-inventory', source, timeout=30)
        (private / 'inventory.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        check(type(result) is dict and result.get('expected_top') == TOP and
              result.get('writes') is False and result.get('file_contents_read') is False and
              result.get('two_snapshots_stable') is True and result.get('resources_closed') is True)
        entries = result['top_entries']
        check(type(entries) is tuple and len(entries) == result['actual_top_count'])
        counts = {kind: 0 for kind in ('directory', 'file', 'symlink', 'other')}
        for row in entries:
            check(type(row) is tuple and len(row) == 3 and row[1] in counts)
            counts[row[1]] += 1
        public.update(top_exact=result['top_exact'], two_snapshots_stable=True,
                      actual_top_count=result['actual_top_count'], type_counts=counts,
                      resources_closed=True, original_fds=result['original_fds'],
                      original_fds_closed=result['original_fds_closed'])
    except BaseException as error:
        failure = error
        public['error_kind'] = type(error).__name__
    # The pinned transport preserves original raw/host exit even on remote failure.
    raw_path = private / '01-sender-top-inventory.stdout.raw'
    exit_path = private / '01-sender-top-inventory.host-exit'
    if raw_path.exists():
        derived = raw_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
        matches = re.findall(r'^MTA_REMOTE_EXIT=(-?[0-9]+)$', derived, re.M)
        if len(matches) == 1:
            public['remote_exit'] = int(matches[0])
            (private / '01-sender-top-inventory.remote-exit').write_text(matches[0], encoding='ascii')
    if exit_path.exists():
        value = exit_path.read_text(encoding='ascii')
        public['host_exit'] = int(value) if re.fullmatch(r'-?[0-9]+', value) else 'TIMEOUT'
    if Path(__file__).read_bytes() != original or transport_path.read_bytes() != transport:
        public['error_kind'] = 'SourceChanged'
        failure = failure or ValueError('source_changed')
    (directory / 'result.json').write_text(json.dumps(public, indent=2), encoding='utf-8')
    print(json.dumps(public, sort_keys=True))
    print('RESULT_DIR=' + str(directory))
    # A known stable mismatch is a successful readonly observation, not stage success.
    return 0 if (failure is None and public['remote_exit'] == 0 and public['host_exit'] == 0) else 1


if __name__ == '__main__':
    if sys.platform == 'win32':
        sys.exit(host_main())
    else:
        run()
