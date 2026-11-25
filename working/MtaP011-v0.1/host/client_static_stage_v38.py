"""Fixed v37 source/WPA package and isolated staging definitions; default PC-only.

No archived driver import, module execution, ADB selection, network or device
mutation in the default path. Physical entry is explicitly unavailable until
the actual ARM read-only baseline/identity/closure adapter is reviewed. A source
package and its StageOwner definitions never produce a ready State factory.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

BASE = Path(__file__).absolute().parents[1]
MANIFEST = BASE / 'host/client_integrated_v37_source_manifest.json'
MANIFEST_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
PARENT_MANIFEST_SHA = '2b13ba05acb3dd4984f7d2c5740349f4d90f1980ebde4014aa63f62a515f721a'
STAGE_SOURCE = BASE / 'candidate/client-static-stage-v38/runtime/mta_client_static_stage.py'
STAGE_SHA = '5f942117e91a9417a1472d73417781e70f196f3eca8147321df21671f2f704d1'
WPA = BASE / 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
MAX_INPUT = 2097152


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, pin, size=None):
    # Same conservative file/parent shape and original opened-file comparison
    # as the reviewed PC source readers; no import/exec follows this read.
    if any(value.is_symlink() for value in (path,) + tuple(path.parents)):
        raise ValueError('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_INPUT:
        raise ValueError('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(MAX_INPUT + 1)
    after = path.stat()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
    if any(getattr(before, name) != getattr(opened, name) or
           getattr(before, name) != getattr(after, name) for name in keys) or \
            before.st_ctime_ns != after.st_ctime_ns or \
            os.name != 'nt' and before.st_ctime_ns != opened.st_ctime_ns or \
            len(raw) != before.st_size or size is not None and len(raw) != size:
        raise ValueError('source_changed')
    if _hash(raw) != pin:
        raise ValueError('source_pin')
    return raw


def _literals(raw):
    # Parse constant data only. No source module/constructor/main is executed.
    values = {}
    for node in ast.parse(raw.decode('utf-8')).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            name = node.targets[0].id
            if name in values:
                raise ValueError('constant_duplicate')
            values[name] = value
    return values


def source_check():
    manifest_raw = _read(MANIFEST, MANIFEST_SHA, 8077)
    tree = json.loads(manifest_raw.decode('utf-8'))
    if type(tree) is not dict or set(tree) != {'schema', 'previous_manifest_sha256', 'sources'} or \
            tree['schema'] != 'client-integrated-v37-host' or \
            tree['previous_manifest_sha256'] != PARENT_MANIFEST_SHA or \
            type(tree['sources']) is not list or len(tree['sources']) != 35:
        raise ValueError('source_manifest')
    stage_raw = _read(STAGE_SOURCE, STAGE_SHA, 16620)
    constants = _literals(stage_raw)
    rows, names = [], set()
    for row in tree['sources']:
        if type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or \
                type(row['module']) is not str or re.fullmatch('[a-z][a-z0-9_]*', row['module']) is None or \
                type(row['path']) is not str or row['path'].startswith('/') or '\\' in row['path'] or \
                any(part in ('', '.', '..') for part in row['path'].split('/')) or \
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= MAX_INPUT or \
                type(row['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None or \
                row['module'] in names:
            raise ValueError('source_row')
        names.add(row['module'])
        rows.append((row['module'], row['bytes'], row['sha256'],
                     _read(BASE / row['path'], row['sha256'], row['bytes'])))
    pins = tuple((name, size, pin) for name, size, pin, raw in rows)
    if constants.get('SOURCE_PINS') != pins or constants.get('SOURCE_MANIFEST_SHA') != MANIFEST_SHA or \
            constants.get('WPA_SHA') != WPA_SHA or constants.get('WPA_BYTES') != WPA_BYTES:
        raise ValueError('stage_source_binding')
    wpa = _read(WPA, WPA_SHA, WPA_BYTES)
    if len(wpa) < 52 or wpa[:7] != b'\x7fELF\x01\x01\x01' or int.from_bytes(wpa[18:20], 'little') != 40:
        raise ValueError('native_shape')
    self_raw = Path(__file__).absolute().read_bytes()
    report = {'schema': 'client-static-stage-v38-source', 'source_check_pass': True,
        'source_count': 35, 'native_bytes': len(wpa), 'source_manifest_sha256': MANIFEST_SHA,
        'driver_sha256': _hash(self_raw), 'stage_source_sha256': STAGE_SHA,
        'physical_entry_available': False, 'reason': 'baseline_adapter_unavailable',
        'adb_invoked': False, 'target_selected': False, 'staging_attempted': False,
        'rf_requested': False, 'source_factory_ready': False, 'deployment_available': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False,
        'restoration_verified': False}
    return report, rows, wpa, manifest_raw, stage_raw


def _candidate(rows):
    return {'version': 1, 'kind': 'client-static-source-v38', 'source_manifest_sha256': MANIFEST_SHA,
        'files': [['runtime/' + name + '.py', size, pin] for name, size, pin, raw in rows] +
                 [['native/mta-wpa-supplicant', WPA_BYTES, WPA_SHA]]}


def build_package():
    # Explicit PC artifact write only. No default packaging and no device path.
    report, rows, wpa, manifest_raw, stage_raw = source_check()
    candidate_raw = json.dumps(_candidate(rows), sort_keys=True).encode('utf-8')
    entries = [('runtime/' + name + '.py', raw) for name, size, pin, raw in rows]
    entries.extend((('native/mta-wpa-supplicant', wpa), ('candidate.json', candidate_raw),
                    ('source-map.json', manifest_raw), ('stage_owner_source.py', stage_raw)))
    if len(entries) != 39 or len(set(name for name, raw in entries)) != 39:
        raise ValueError('package_shape')
    parent = BASE / 'results'
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('package_parent')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = parent / ('client-static-stage-v38-package-' + stamp + '-' + os.urandom(4).hex())
    output.mkdir(exist_ok=False)
    archive = output / 'private-source-package.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in entries:
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive, 'r') as bundle:
        if bundle.namelist() != [name for name, raw in entries] or bundle.testzip() is not None:
            raise ValueError('package_readback')
        for name, raw in entries:
            info = bundle.getinfo(name)
            if info.file_size != len(raw) or bundle.read(name) != raw:
                raise ValueError('package_readback')
    report.update(package_written=True, package_bytes=archive.stat().st_size,
        package_sha256=_hash(archive.read_bytes()), candidate_sha256=_hash(candidate_raw))
    (output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (output / 'README.txt').write_text('PC static sources/WPA package only; no ADB or device writes.\n'
        '39 fixed ZIP members are read back and CRC checked; candidate.json is not deployment.json.\n'
        'No GATT credentials, LoadedDeployment, RF permission, State readiness or restoration result.\n'
        'Physical entry remains baseline_adapter_unavailable. Old stages and user directories untouched.\n', encoding='utf-8')
    report['package_directory'] = str(output)
    return report


def execute_stage_unavailable(expected, transport):
    # Explicit intended transport is required, but is never selected or used
    # while the native preflight adapter is absent. No fallback to old main.
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None or \
            type(transport) is not str or re.fullmatch('[1-9][0-9]{0,9}', transport) is None:
        raise ValueError('physical_input')
    report = source_check()[0]
    if expected != report['driver_sha256']:
        raise ValueError('driver_pin')
    report.update(physical_entry_requested=True, transport_supplied=True,
        reason='baseline_adapter_unavailable', physical_entry_available=False)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', action='store_true')
    parser.add_argument('--execute-stage-reviewed', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    parser.add_argument('--transport-id')
    args = parser.parse_args(argv)
    physical = args.execute_stage_reviewed
    if args.package and physical or physical != (args.expected_driver_sha256 is not None) or \
            physical != (args.transport_id is not None):
        parser.error('Physical reviewed SHA and explicit transport must be supplied together; package is PC-only')
    try:
        report = execute_stage_unavailable(args.expected_driver_sha256, args.transport_id) if physical else \
                 build_package() if args.package else source_check()[0]
        print(json.dumps(report, indent=2))
        return 2 if physical else 0
    except Exception:
        print(json.dumps({'source_check_pass': False, 'reason': 'source_or_package_invalid',
            'adb_invoked': False, 'staging_attempted': False, 'rf_requested': False,
            'source_factory_ready': False, 'receive_available': False, 'send_available': False,
            'phone_tested': False, 'restoration_verified': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
