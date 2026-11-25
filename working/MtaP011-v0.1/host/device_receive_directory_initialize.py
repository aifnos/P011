"""Explicit P011 component: initialize only the fixed Received child, no RF."""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
PROBE_PIN = 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'
RUNTIME = 'candidate/receive-directory-fd-v1/runtime/mta_storage.py'
SOURCES = (('p011_json', 'runtime/p011_json.py'), ('mta_protocol', 'runtime/mta_protocol.py'),
    ('mta_storage', RUNTIME))
BODY = r'''
import base64, errno, hashlib, os, stat, sys, time, types
until = time.monotonic() + 10.0
user = child = before = after = None
failure = None
close_errors = []
created = False
volume_checked = False
expected_components = ('/', 'mnt', 'data', 'p011-toolbox', 'user')
stock_pins = {
 '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
 '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
 '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
def check():
    if time.monotonic() >= until: raise ValueError('original_deadline')
def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as source:
        for raw in iter(lambda: source.read(65536), b''):
            check()
            value.update(raw)
    return value.hexdigest()
def baseline():
    check()
    result = dict(boot=digest('/proc/sys/kernel/random/boot_id'),
        pending=digest('/var/volatile/tmp/p011-mta-p2p-device.pending'),
        routes=digest('/proc/net/route'), interfaces=tuple(sorted(os.listdir('/sys/class/net'))),
        stock=dict((path, digest(path)) for path in stock_pins))
    if result['stock'] != stock_pins: raise ValueError('stock_identity_changed')
    check()
    return result
def policy(binding, components):
    binding.check()
    rows = binding.identity_rows()
    if len(rows) != len(components): raise ValueError('directory_count')
    for row, name in zip(rows, components):
        if (type(row) is not tuple or len(row) != 6 or row[0] != name or
                not stat.S_ISDIR(row[3]) or row[3] & 0o022): raise ValueError('directory_policy')
        expected_owner = (1000, 1000) if name == 'data' else (0, 0)
        if row[4:] != expected_owner: raise ValueError('directory_owner')
        if name == 'data' and stat.S_IMODE(row[3]) != 0o755: raise ValueError('data_mode')
        if name in ('p011-toolbox', 'user', 'Received') and stat.S_IMODE(row[3]) != 0o700:
            raise ValueError('private_directory_mode')
    binding.check()
    return rows
try:
    if sys.platform != 'linux' or os.geteuid() != 0 or os.uname()[4] != 'armv7l':
        raise ValueError('platform')
    before = baseline()
    for name, encoded, pin in source_data:
        check()
        raw = base64.b64decode(encoded.encode('ascii'), validate=True)
        if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('source_changed')
        if name in sys.modules: raise ValueError('preloaded_module')
        module = types.ModuleType(name)
        module.__file__ = '<mta-component-' + name + '>'
        sys.modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        check()
    storage = sys.modules['mta_storage']
    user = storage.DirectoryBinding.__new__(storage.DirectoryBinding)
    storage.DirectoryBinding.__init__(user, '/mnt/data/p011-toolbox/user', until, clock=time.monotonic)
    original_rows = policy(user, expected_components)
    try:
        os.stat(b'Received', dir_fd=user.fd(), follow_symlinks=False)
        was_absent = False
    except OSError as error:
        if error.errno != errno.ENOENT: raise
        was_absent = True
    child = user.ensure_private_child('Received')
    created = user.initializations[-1]['created'] is True
    if created is not was_absent: raise ValueError('unexpected_child_creation')
    rows = policy(child, expected_components + ('Received',))
    if rows[:-1] != original_rows or child.absolute_until is not until or child.clock is not time.monotonic:
        raise ValueError('original_directory_relationship')
    if os.listdir(child.fd()) != []: raise ValueError('received_not_empty')
    volume = os.fstatvfs(child.fd())
    if volume.f_frsize <= 0 or volume.f_bavail < 0: raise ValueError('volume_unknown')
    volume_checked = True
    user.check(); child.check()
    after = baseline()
    if after != before: raise ValueError('baseline_changed')
except BaseException as error:
    failure = type(error).__name__ + ':' + str(error)
finally:
    partial_child = None
    if user is not None and getattr(user, 'initializations', None):
        original_ticket = user.initializations[-1]
        created = original_ticket['created'] if original_ticket['returned'] or not original_ticket['called'] else None
        partial_child = original_ticket['child']
    close_bindings = [('child', child), ('user', user)]
    if partial_child is not None and partial_child is not child:
        close_bindings.insert(0, ('partial_child', partial_child))
    for label, binding in close_bindings:
        if binding is None: continue
        try:
            if binding.close() is not True or binding.closed() is not True:
                raise ValueError('original_close_unknown')
        except BaseException as error: close_errors.append((label, type(error).__name__))
bindings = [binding for label, binding in close_bindings if binding is not None]
rows = [row for binding in bindings for row in binding.rows]
print('RESULT=' + repr(dict(passed=failure is None and not close_errors,
    failure=failure, created_received=created, initialized=child is not None,
    baseline_unchanged=before is not None and after == before,
    volume_checked=volume_checked,
    directory_fd_count=len(rows), closed_fd_count=sum(row['closed'] is True and row['unknown'] is False for row in rows),
    close_errors=close_errors, no_other_target_writes=True, no_target_deletes=True,
    runtime_deployed=False, rf=False, full_receive=False, phone=False, admission=False)))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize-received', action='store_true', required=True)
    parser.parse_args()
    names = tuple(path for name, path in SOURCES) + ('host/device_probe.py',
        'host/device_receive_directory_initialize.py', 'TEST_MTA_RECEIVE_DIRECTORY_INITIALIZE.cmd')
    originals = {path: (BASE / path).read_bytes() for path in names}
    if hashlib.sha256(originals['host/device_probe.py']).hexdigest() != PROBE_PIN:
        raise ValueError('host_probe_changed')
    data = tuple((name, base64.b64encode(originals[path]).decode('ascii'),
        hashlib.sha256(originals[path]).hexdigest()) for name, path in SOURCES)
    lines = ['source_data = (']
    for name, encoded, pin in data:
        lines.extend(['    (' + repr(name) + ',', '     ('])
        lines.extend('      ' + repr(encoded[index:index + 1024]) for index in range(0, len(encoded), 1024))
        lines.extend(['     ),', '     ' + repr(pin) + '),'])
    lines.append(')')
    target = '\n'.join(lines) + '\n' + BODY
    target_raw = target.encode('ascii')
    if len(target_raw) > 160000 or max(map(len, target_raw.splitlines())) > 2048:
        raise ValueError('target_source_transport_limit')
    ast.parse(target, feature_version=(3, 5))
    out = BASE / 'results' / ('receive-directory-initialize-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        dest = private / 'inputs' / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        if dest.read_bytes() != raw: raise ValueError('snapshot_changed')
    (private / 'target-source.py').write_bytes(target.encode('ascii'))
    from device_probe import Adb
    observed, host_failure = None, None
    try:
        observed = Adb(private).python('receive-directory-initialize', target, timeout=25)
    except BaseException as error:
        host_failure = type(error).__name__
    (private / 'remote-result.json').write_bytes((json.dumps(observed, indent=2) + '\n').encode('ascii'))
    unchanged = all((BASE / path).read_bytes() == raw and (private / 'inputs' / path).read_bytes() == raw
        for path, raw in originals.items())
    passed = (host_failure is None and type(observed) is dict and observed.get('passed') is True and
        observed.get('directory_fd_count') == 11 and observed.get('closed_fd_count') == 11 and
        observed.get('baseline_unchanged') is True and observed.get('volume_checked') is True and unchanged)
    report = dict(passed=passed, actual_p011=True, host_failure=host_failure,
        target_failure_type=observed['failure'].split(':', 1)[0] if type(observed) is dict and observed.get('failure') else None,
        created_received=observed.get('created_received') if type(observed) is dict else None,
        volume_checked=observed.get('volume_checked') if type(observed) is dict else False,
        baseline_unchanged=observed.get('baseline_unchanged') if type(observed) is dict else False,
        directory_fd_count=observed.get('directory_fd_count') if type(observed) is dict else None,
        closed_fd_count=observed.get('closed_fd_count') if type(observed) is dict else None,
        source_snapshots_equal=unchanged, rf=False, full_receive=False, phone=False, admission=False,
        target_deleted=False, runtime_deployed=False, target_changed_only_fixed_received=True if passed else None,
        inputs=[dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for path, raw in originals.items()],
        target_sha256=hashlib.sha256(target.encode('ascii')).hexdigest(), raw_identifiers_included=False)
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Explicit P011 component: actual candidate DirectoryBinding opens the existing user chain, '
        b'initializes only fixed Received/0700 when absent, checks original relationships, empty child and fstatvfs, '
        b'then once-closes original directory FDs. Stock hashes/boot/pending bytes/IPv4 route text/netdev names are compared. '
        b'Created Received is retained; no ancestor mkdir/chmod/chown/delete, runtime deployment, RF, '
        b'full receive, phone, old pending retirement or production admission. Failure raw remains private.\n')
    members = {'result.json': result, 'README.txt': readme}
    for name, raw in members.items(): (out / name).write_bytes(raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(name) != raw for name, raw in members.items()): raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
