"""Two fixed CLIENT source trees: SOURCE by default; explicit conditional archive.

--verify-device only hashes the fixed62 files and obtains fresh bounded collision
observations. --archive does this first, pulls both exact directories into new
PC-local private storage, checks every backup byte and the private ZIP, then
freshly verifies originals/collisions before exactly two FD-relative renames.
No old test replay, service/RF, journal read/lock, deletion, rollback or grant.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
ARCHIVER = ('candidate/client-source-archive-v1/runtime/client_source_archive.py', 16533,
    '5d380be2b0a1834c97ec6e67c0f6837886921fcf12ee67f3229a04f36c025f15')
EXPECTED_SOURCE = ('candidate/client-source-archive-v1/runtime/expected_source.py', 7897,
    'b060dcf92be8dca21907b89365cb5158235d2a2e05bf27d7baf300f5030b4555')
PROC = ('candidate/client-source-proc-readonly-v1/runtime/client_source_proc.py', 12673,
    'a199f4622cb02a0b3d942c6d98dcbf0400d76ebe06097140aa73a68d42a4f1c6')
JSON_SOURCE = ('runtime/p011_json.py', 8061,
    'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
ORIGINS = (
    ('host/client_init_tmp_alias_v11_p011.py', 13573,
     '89a982b0fba22e9720e00a98d95a84547287d38945567f2a53c639e8c5f09248'),
    ('host/client_init_prepare_v10_p011.py', 34010,
     'cb50e2a92b669b64061f9872bcbb27265d3b3818517cc95cfabeaef3f8e714df'),
    ('candidate/client-static-stage-v40/runtime/mta_client_static_stage.py', 28860,
     'e0b4b1d596ca629024cebef6fbee53218bbbc26ad53a1a2d163d36d6bb40c3e0'),
    ('candidate/client-static-stage-v40-r2/runtime/mta_client_static_stage.py', 30601,
     '64773fe9a3c75f9cce8e9938dc8f9dc1d4914e4d00728dcef728d686b90ba0a2'),
    ('results/client-source-metadata-readonly-v1-readonly-20261004-205654-2bdd781d/private-raw/01-history.stdout.raw',
     35276, '603c2f5f1bc4962028b1eecb919089d53b12e5fa2abf1a819cc9eb2e83e090dc'))
SELF = 'host/device_client_source_archive_v1_check.py'
CMD = 'ARCHIVE_MTA_CLIENT_SOURCE_V1.cmd'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-client-rfinit'
BOOLS = ('verified', 'archive_verified', 'archive_created', 'device_mutations',
    'resources_closed', 'all_process_fds_scanned', 'exclusive_lease',
    'restoration_verified', 'receive_admission', 'radio_operations')
COUNTS = ('rename_called', 'rename_returned', 'rename_verified')
PRIVATE = ('private_inventory', 'private_after', 'private_proc', 'private_events', 'private_error')
FIELDS = frozenset(('reason',) + BOOLS + COUNTS + PRIVATE)
ALWAYS_FALSE = ('all_process_fds_scanned', 'exclusive_lease', 'restoration_verified',
                'receive_admission', 'radio_operations')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise OSError('short_write')


def assigned(raw, key):
    tree = ast.parse(raw.decode('utf-8'))
    nodes = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
             for target in node.targets if isinstance(target, ast.Name)}
    def resolve(node):
        if isinstance(node, ast.Name): return resolve(nodes[node.id])
        if isinstance(node, (ast.Tuple, ast.List)):
            values = [resolve(item) for item in node.elts]
            return tuple(values) if isinstance(node, ast.Tuple) else values
        if isinstance(node, ast.Dict): return {resolve(k): resolve(v) for k, v in zip(node.keys, node.values)}
        return ast.literal_eval(node)
    return resolve(nodes[key])


def source_plan(inputs):
    plan = assigned(inputs[EXPECTED_SOURCE[0]], 'EXPECTED')
    if (type(plan) is not tuple or len(plan) != 2 or [len(rows) for name, rows in plan] != [24, 38] or
            sum(row[1] for name, rows in plan for row in rows) != 4548465): raise ValueError('plan_shape')
    raw = inputs[ORIGINS[-1][0]].decode('utf-8').replace('\r\r\n', '\n').replace('\r\n', '\n')
    results = [line[7:] for line in raw.splitlines() if line.startswith('RESULT=')]
    if len(results) != 1: raise ValueError('origin_result')
    sampled = ast.literal_eval(results[0])
    originals = {item['tag']: item for item in sampled['private_files']}
    docs = {tag: json.loads(item['raw']) for tag, item in originals.items()}
    for index, (name, rows) in enumerate(plan):
        tags = ('candidate_1', 'deployment_1') if index == 0 else ('candidate_2', 'static_source_2')
        expected = tuple((path, size, sha, 0o500 if path.startswith('native/') else 0o400)
                         for path, size, sha in docs[tags[0]]['files'])
        expected += tuple(('candidate.json' if tag.startswith('candidate') else
            'deployment.json' if index == 0 else 'static-source.json',
            len(originals[tag]['raw'].encode('utf-8')), originals[tag]['sha256'], 0o400) for tag in tags)
        if index == 0: expected += (('journal.lock', 0, digest(b''), 0o600),)
        if rows != expected or any(digest(originals[tag]['raw'].encode('utf-8')) != originals[tag]['sha256'] for tag in tags):
            raise ValueError('origin_plan')
    v10, v11 = inputs[ORIGINS[1][0]], inputs[ORIGINS[0][0]]
    replacements = assigned(v11, '_NEW_PINS')
    pins11 = []
    for name, sha in assigned(v10, 'PINS'):
        pins11.append((name, replacements.get(name, sha)))
        if name == 'mta_ip': pins11.append(('mta_client_tmp_alias', replacements['mta_client_tmp_alias']))
    if ([(path[8:-3], sha) for path, size, sha, mode in plan[0][1] if path.startswith('runtime/')] != pins11 or
            docs['candidate_1']['driver_sha256'] != digest(v11) or
            docs['deployment_1']['sources'] != [list(row) for row in pins11] or
            docs['deployment_1']['provider']['candidate_sha'] != originals['candidate_1']['sha256']):
        raise ValueError('v11_origin')
    for pin in ORIGINS[2:4]:
        raw = inputs[pin[0]]
        if [(path[8:-3], size, sha) for path, size, sha, mode in plan[1][1] if path.startswith('runtime/')] != list(assigned(raw, 'SOURCE_PINS')):
            raise ValueError('v40_origin')
        candidate = docs['candidate_2']; record = docs['static_source_2']
        for key, constant in (('staged_native_map_sha256', 'SOURCE_MANIFEST_SHA'),
                ('loaded_readonly_map_sha256', 'READONLY_MANIFEST_SHA'), ('readonly_leaf_sha256', 'READONLY_LEAF_SHA')):
            if candidate[key] != assigned(raw, constant) or record[key] != candidate[key]: raise ValueError('v40_map')
        if (candidate['kind'] != 'client-static-source-v40' or record['kind'] != 'static-source-not-ready' or
                record['candidate_sha256'] != originals['candidate_2']['sha256'] or
                record['sources'] != [list(row) for row in assigned(raw, 'SOURCE_PINS')] or
                any(record[key] is not False for key in ('deployment_available', 'source_factory_ready',
                    'device_exclusive_lease', 'rf_admission', 'rf_requested', 'send_available', 'receive_available', 'phone_tested'))):
            raise ValueError('v40_record')
        for name, rows in plan:
            native = next(row for row in rows if row[0].startswith('native/'))
            if native[1:3] != (assigned(raw, 'WPA_BYTES'), assigned(raw, 'WPA_SHA')): raise ValueError('native_origin')
    return plan


def target_source(inputs, action='verify', token=None, inventory=None):
    if action not in ('verify', 'archive'): raise ValueError('action')
    lines = ['import hashlib,sys,types', 'modules=(']
    for tag, pin in (('p011_json', JSON_SOURCE), ('expected_source', EXPECTED_SOURCE),
                     ('client_source_proc_readonly', PROC), ('client_source_archive', ARCHIVER)):
        lines.append('(' + repr(tag) + ',' + str(pin[1]) + ',' + repr(pin[2]) + ',(')
        raw = inputs[pin[0]]
        for offset in range(0, len(raw), 256): lines.append(' ' + repr(raw[offset:offset + 256]) + ',')
        lines.append(')),')
    lines.extend((')', 'for name,size,sha,chunks in modules:', ' raw=b"".join(chunks)',
        ' if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("source_pin")',
        ' module=types.ModuleType(name);sys.modules[name]=module',
        ' exec(compile(raw,"<fixed-client-source-archive-v1>","exec"),module.__dict__)'))
    if action == 'archive':
        if type(token) is not str or re.fullmatch('[0-9a-f]{24}', token) is None or type(inventory) is not dict:
            raise ValueError('archive_request')
        raw = json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode('ascii')
        if len(raw) > 32768: raise ValueError('inventory_budget')
        lines.append('chunks=(')
        for offset in range(0, len(raw), 256): lines.append(' ' + repr(raw[offset:offset + 256]) + ',')
        lines.extend((')', 'raw=b"".join(chunks)',
            'if len(raw)!=' + str(len(raw)) + ' or hashlib.sha256(raw).hexdigest()!=' + repr(digest(raw)) + ':raise ValueError("inventory_pin")',
            'inventory=sys.modules["p011_json"].loads(raw.decode("ascii"))',
            'value=sys.modules["client_source_archive"].archive(' + repr(token) + ',inventory)'))
    else: lines.append('value=sys.modules["client_source_archive"].verify()')
    lines.extend(('print("RESULT="+repr(value))', 'print("MTA_REMOTE_OK")'))
    raw = ('\n'.join(lines) + '\n').encode('ascii')
    if len(raw) > 128 * 1024 or any(len(line) > 2048 for line in raw.splitlines()): raise ValueError('program_budget')
    ast.parse(raw.decode('ascii'), feature_version=(3, 5)); return raw


def observed_remote_exit(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    values = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
    return int(values[0]) if len(values) == 1 else 'UNKNOWN'


def parse_result(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    values = [line[7:] for line in text.splitlines() if line.startswith('RESULT=')]
    if observed_remote_exit(raw) != 0 or text.splitlines().count('MTA_REMOTE_OK') != 1 or len(values) != 1:
        raise ValueError('result_unknown')
    value = ast.literal_eval(values[0])
    if (type(value) is not dict or set(value) != FIELDS or any(type(value[key]) is not bool for key in BOOLS) or
            any(value[key] is not False for key in ALWAYS_FALSE) or
            any(type(value[key]) is not int or not 0 <= value[key] <= 2 for key in COUNTS) or
            value['reason'] not in ('not_started', 'verified_readonly', 'archived', 'archive_partial', 'verification_refused')):
        raise ValueError('result_fields')
    return value


def remote(adb, label, source):
    command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(40);'
        'exec(sys.stdin.buffer.read(' + str(len(source)) + '))" p011-client-source-archive-v1; '
        'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    return adb.run(label, ['shell', command], timeout=50, input_data=source)


def verified(value):
    return (value['reason'] == 'verified_readonly' and value['verified'] and value['resources_closed'] and
            not value['device_mutations'] and value['rename_called'] == 0 and
            type(value['private_inventory']) is dict and value['private_error'] is None)


def backup(adb, out, plan, inventory):
    root = out / 'private-backup'; root.mkdir(exist_ok=False)
    unix = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii')
    write_new(root / 'unix-stat-inventory.json', unix)
    members, raw_files = {}, {}
    for index, (name, specs) in enumerate(plan, 1):
        branch = root / ('tree-' + str(index))
        if branch.exists(): raise ValueError('backup_destination_exists')
        adb.run('backup-' + str(index), ['pull', PHYSICAL_ROOT + '/' + name, str(branch)], timeout=30)
        wanted_files = {relative for relative, size, sha, mode in specs}
        found_files, found_dirs = set(), set()
        for parent, dirs, files in os.walk(branch, followlinks=False):
            here = Path(parent)
            if here.is_symlink() or not here.is_dir(): raise ValueError('backup_directory')
            relative = here.relative_to(branch).as_posix()
            found_dirs.add('' if relative == '.' else relative)
            for child in dirs:
                if (here / child).is_symlink(): raise ValueError('backup_link')
            for child in files:
                path = here / child
                if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode): raise ValueError('backup_file')
                found_files.add(path.relative_to(branch).as_posix())
        if found_files != wanted_files or found_dirs != {'', 'runtime', 'native', 'ctrl'}:
            raise ValueError('backup_inventory')
        saved_runs = inventory['runs']
        original_dirs = next(dirs for run, dirs, files in saved_runs if run == name)
        original_files = next(files for run, dirs, files in saved_runs if run == name)
        for relative, meta in original_dirs:
            member = 'tree-' + str(index) + '/' + (relative + '/' if relative else '')
            members[member] = (b'', meta[2])
        for relative, size, sha, mode in specs:
            path = branch / relative
            before = path.stat(); raw = path.read_bytes(); after = path.stat()
            if (before.st_size != size or len(raw) != size or digest(raw) != sha or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError('backup_fingerprint')
            original = next(meta for path, meta, pin in original_files if path == relative)
            member = 'tree-' + str(index) + '/' + relative
            members[member] = (raw, original[2]); raw_files[str(path.relative_to(root))] = (size, sha)
    members['unix-stat-inventory.json'] = (unix, stat.S_IFREG | 0o600)
    archive = root / 'originals.private.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted(members):
            raw, mode = members[name]
            info = zipfile.ZipInfo(name); info.create_system = 3
            info.external_attr = mode << 16; info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, raw)
    with zipfile.ZipFile(archive) as bundle:
        if sorted(bundle.namelist()) != sorted(members) or len(bundle.namelist()) != 71:
            raise ValueError('backup_zip_inventory')
        for name, (raw, mode) in members.items():
            if bundle.read(name) != raw or bundle.getinfo(name).external_attr >> 16 != mode:
                raise ValueError('backup_zip_readback')
    # Final local originals recheck, not just the ZIP's stored copies.
    for relative, (size, sha) in raw_files.items():
        raw = (root / relative).read_bytes()
        if len(raw) != size or digest(raw) != sha: raise ValueError('backup_tail_changed')
    return archive, digest(archive.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--verify-device', action='store_true')
    modes.add_argument('--archive', action='store_true')
    args = parser.parse_args()
    mode = 'archive' if args.archive else 'verify' if args.verify_device else 'source'
    out = BASE / 'results' / ('client-source-archive-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False); private = out / 'private-raw'; private.mkdir()
    inputs, before, after, calls = {}, None, None, []
    report = dict(schema='p011-two-client-source-conditional-archive-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False,
        readonly_verified=False, backup_verified=False, backup_zip_sha256=None,
        archive_attempted=False, archive_verified=False, device_mutations=False,
        rename_called=0, rename_returned=0, rename_verified=0, resources_closed=False,
        files_expected=62, directories_expected=8, bytes_expected=4548465,
        old_tests_replayed=0, service_started=False, owner_loaded=False, locks_taken=False,
        journal_contents_read=False, radio_operations=False, all_process_fds_scanned=False,
        exclusive_lease=False, restoration_verified=False, receive_admission=False,
        concurrent_actor_race_excluded=False, host_error=None,
        operation_seconds=30, proc_observation_seconds=10, remote_alarm_seconds=40,
        host_remote_timeout_seconds=50, host_pull_timeout_seconds=30,
        source_scope='fixed_syntax_provenance_and_transport_only')
    try:
        for path, size, sha in (ARCHIVER, EXPECTED_SOURCE, PROC, JSON_SOURCE, TRANSPORT) + ORIGINS:
            raw = (BASE / path).read_bytes()
            if len(raw) != size or digest(raw) != sha: raise ValueError('source_pin')
            inputs[path] = raw
        for path in (SELF, CMD): inputs[path] = (BASE / path).read_bytes()
        for path, raw in inputs.items():
            target = out / 'private-inputs' / path; target.parent.mkdir(parents=True, exist_ok=True)
            write_new(target, raw)
            if path.endswith('.py'): ast.parse(raw.decode('utf-8'), feature_version=(3, 5) if path == ARCHIVER[0] else None)
        write_new(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        plan = source_plan(inputs); source = target_source(inputs)
        write_new(out / 'private-verify-target.py', source)
        report.update(source_checked=True, source_count=len(inputs), target_bytes=len(source), target_sha256=digest(source))
        if mode != 'source':
            module = types.ModuleType('fixed_client_archive_transport'); module.__file__ = str(BASE / TRANSPORT[0])
            exec(compile(inputs[TRANSPORT[0]], str(BASE / TRANSPORT[0]), 'exec'), module.__dict__)
            adb = module.Adb(private); report['device_invoked'] = True
            raw = remote(adb, 'verify', source); before = parse_result(raw)
            if not verified(before): raise ValueError('readonly_refused')
            report['readonly_verified'] = True; report['resources_closed'] = before['resources_closed']
            write_new(out / 'private-before.json', (json.dumps(before, sort_keys=True, indent=2) + '\n').encode('ascii'))
            if args.archive:
                archive, sha = backup(adb, out, plan, before['private_inventory'])
                report.update(backup_verified=True, backup_zip_sha256=sha)
                # No fixed paths are accepted from CLI or a browser. The
                # original inventory is held in this invocation, not reloaded
                # from an arbitrary receipt. Backup must fully pass first.
                source = target_source(inputs, 'archive', secrets.token_hex(12), before['private_inventory'])
                write_new(out / 'private-archive-target.py', source)
                report['archive_attempted'] = True
                raw = remote(adb, 'archive', source); after = parse_result(raw)
                for key in ('archive_verified', 'device_mutations', 'resources_closed') + COUNTS:
                    report[key] = after[key]
                # Preserve actual mutation/rename facts even if serializing a
                # private diagnostic containing bytes fails on the host.
                write_new(out / 'private-after.json', (json.dumps(after, sort_keys=True, indent=2) + '\n').encode('ascii'))
                if (after['reason'] != 'archived' or not after['archive_verified'] or not after['resources_closed'] or
                        any(after[key] != 2 for key in COUNTS)):
                    raise ValueError('archive_pending')
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        for path in sorted(private.glob('*.host-exit')):
            stem = path.name[:-10]
            stdout = private / (stem + '.stdout.raw'); stderr = private / (stem + '.stderr.raw')
            raw = stdout.read_bytes() if stdout.exists() else b''
            text = path.read_text(encoding='ascii').strip()
            calls.append(dict(step=stem.split('-', 1)[-1], host_exit=int(text) if re.fullmatch(r'-?\d+', text) else 'TIMEOUT',
                remote_exit=observed_remote_exit(raw) if stem.endswith(('verify', 'archive')) else 'NOT_APPLICABLE',
                stdout_bytes=len(raw), stdout_sha256=digest(raw),
                stderr_bytes=stderr.stat().st_size if stderr.exists() else None,
                stderr_sha256=digest(stderr.read_bytes()) if stderr.exists() else None))
        report['calls'] = calls
        report['source_preserved'] = bool(inputs) and all((BASE / path).read_bytes() == raw and
            (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items())
        # Remote result may be lost after a mutation, including alarm/transport
        # expiry. Do not turn absence of RESULT into a false no-write claim.
        if report['archive_attempted'] and after is None:
            report['device_mutations'] = 'UNKNOWN'
            report['resources_closed'] = False
    report['passed'] = report['source_checked'] and report['source_preserved'] and report['host_error'] is None and (
        mode == 'source' or report['readonly_verified'] and (mode == 'verify' or report['backup_verified'] and report['archive_verified']))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Only two human-authorized source directories. Fixed62 files/8 directories/4548465 original bytes. '
        b'SOURCE parses provenance and framing only, never executes target definitions. Verify hashes actual files '
        b'with held NOFOLLOW directory descriptors; root-owned modes and complete exact names required. '
        b'Archive additionally pulls two fixed paths, byte-checks every local original and reads back a private '
        b'71-member ZIP containing originals,8 directory entries and Unix-stat inventory. Only then fresh source '
        b'and bounded proc/ctrl/lock observations are made before mkdir one new EXCL0700 archive bucket and '
        b'exactly two os.rename calls. No overwrite/deletion/rollback, services, RF, signal, journal read or lock. '
        b'Parent and original inode/mode/size/mtime/hash readbacks are checked. Directory ctime may change by rename; '
        b'original and actual values remain private. Partial failure stays recorded, never declared restored. '
        b'Proc scans bounded exe/argv and only matching actor FD links; all-fd absence and exclusion of a new actor '
        b'between observation and rename are not proved. Concurrent_actor_race_excluded/exclusive_lease/admission/'
        b'restoration stayFalse. Private originals,Unix stat,manifests,path/token/PID data never enter this public ZIP.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('public_zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out), public_result_zip=str(bundle_path),
        zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
