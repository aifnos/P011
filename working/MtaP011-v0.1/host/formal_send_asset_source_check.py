"""Fixed PC-only asset audit; never import target code or touch a device."""
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import struct
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
ASSETS = 'candidate/formal-send-v1/assets/asset-sources.json'
MANIFEST = 'candidate/formal-send-v1/assets/sender-source-manifest.json'
PUBLISHER = 'candidate/formal-send-v1/runtime/mta_go_send_publication.py'
PREVIOUS = 'candidate/go-send-preflight-key-v90/runtime/mta_go_send_publication.py'
CHECKER = 'host/formal_send_asset_source_check.py'
ENTRY = 'HOST_MTA_FORMAL_SEND_ASSET_CHECK.cmd'
FIXED = {
    ASSETS: (23552, '27366f2510d07f2dd74eb65533c314f48d7b437bb574744c57203e28746a076a'),
    MANIFEST: (3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
    PUBLISHER: (45712, 'db8a41485c130cdcad21de3292ef0d923dbee1774a34b3315a346e1c05ca7b99'),
    'host/go_send_fixed_terminal_v98_asset_sources.json':
        (5634, 'c6293f477248dd36c7b8ad695527ae65901225d7ac976432ea953dd90d87fc3c'),
    'host/go_readonly_terminal_v97_asset_sources.json':
        (9751, '8205740cb49b819923845f126a6fb1e22d04a614877bcac4e10ea3533705c5cc'),
}
BASELINE = [
    ['/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'],
    ['/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'],
    ['/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'],
    ['/usr/sbin/wpa_cli', 'e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849'],
]
OBSERVER_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, code):
    if not value:
        raise ValueError(code)


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'short_write')
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'snapshot_readback')


def parse(raw):
    return ast.parse(raw, feature_version=(3, 5))


def literal(tree, name, seen=()):
    require(name not in seen and len(seen) < 20, 'literal_dependency_cycle')
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name
                       for target in node.targets)]
    require(len(matches) == 1, 'unique_literal')
    class ResolveConstants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(value=literal(tree, node.id, seen + (name,)))
    # Resolve only top-level literal constants, never eval target expressions.
    value = ResolveConstants().visit(matches[0])
    return ast.literal_eval(value)


def publisher_body(raw):
    tree = parse(raw)
    while tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(
            tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
        tree.body.pop(0)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == 'BUNDLE_MANIFEST_SHA' for target in node.targets):
            node.value = ast.Constant(value=None)
    return ast.dump(tree, include_attributes=False)


def main():
    if sys.argv[1:]:
        raise ValueError('fixed_SOURCE_only_no_arguments')
    out = BASE / 'results' / ('formal-send-assets-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-formal-send-assets-source-v1', passed=False,
        host_exit=None, remote_exit=None, source_only=True, runtime_graph=False,
        admission=False, native_startup_verified=False, restoration_verified=False,
        device=False, phone=False, old_tests=0, error=None)
    snapshots = {}
    trees = {}

    def read(name):
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and
                '\\' not in name and path.as_posix() == name, 'relative_source_path')
        if name not in snapshots:
            snapshots[name] = (BASE / name).read_bytes()
            save(out / 'private-inputs' / name, snapshots[name])
        raw = snapshots[name]
        if name in FIXED:
            require((len(raw), digest(raw)) == FIXED[name], 'fixed_source_pin')
        return raw

    try:
        for name in (CHECKER, ENTRY, ASSETS, MANIFEST, PUBLISHER, PREVIOUS):
            read(name)
        assets = json.loads(read(ASSETS))
        manifest = json.loads(read(MANIFEST))
        require(assets['schema'] == 'p011-formal-send-v1-fixed-asset-sources' and
                assets['scope'] == 'SOURCE_ONLY_UNADMITTED', 'asset_scope')
        require(all(assets[key] is False for key in ('admission', 'native_startup_verified',
                'restoration_verified', 'device', 'phone')), 'source_only_flags')
        require(assets['source_mode'] == '0400' and assets['directory_mode'] == '0700', 'asset_modes')
        require(assets['observer_load_count'] == 38 and
                assets['observer_readonly_manifest_sha256'] == OBSERVER_SHA, 'observer_load_contract')
        for kind, count, total, root in (
                ('sender', 25, 1047589, '/var/volatile/tmp/p011-mta-go-send-v76-assets'),
                ('observer', 41, 1440449, '/var/volatile/tmp/p011-mta-go-observer-v85')):
            rows = assets[kind + '_sources']
            table_name, table_size, table_sha = assets[kind + '_source_table']
            raw = read(table_name)
            require((len(raw), digest(raw)) == (table_size, table_sha), 'original_table_pin')
            table = json.loads(raw)['sources']
            require(assets[kind + '_root'] == root and len(rows) == count and
                    assets[kind + '_source_count'] == count and
                    assets[kind + '_source_bytes'] == total and len(table) == count,
                    'role_count_root')
            require(len({row['module'] for row in rows}) == count and
                    len({row['target'] for row in rows}) == count and
                    len({row['source'] for row in rows}) == count, 'role_uniqueness')
            for row, original in zip(rows, table):
                require(set(row) == {'module', 'source', 'target', 'bytes', 'sha256'} and
                        (row['module'], row['source'], row['bytes'], row['sha256']) ==
                        (original['module'], original['path'], original['bytes'], original['sha256']) and
                        row['target'] == root + '/runtime/' + row['module'] + '.py', 'original_role_mapping')
                raw = read(row['source'])
                require((len(raw), digest(raw)) == (row['bytes'], row['sha256']), 'role_bytes')
                trees[row['source']] = parse(raw)
            require(sum(row['bytes'] for row in rows) == total, 'role_total')
            report[kind + '_source_count'] = count
            report[kind + '_source_bytes'] = total
        sender_rows = assets['sender_sources']
        require(manifest['schema'] == 'p011-go-send-assets-v76' and
                manifest['sources'] == [[row['module'], row['bytes'], row['sha256']]
                    for row in sender_rows] and manifest['baseline_manifest'] == BASELINE,
                'complete_sender_manifest')
        require(assets['sender_manifest']['source'] == MANIFEST and
                assets['sender_manifest']['target'] == assets['sender_root'] + '/source-manifest.json' and
                (assets['sender_manifest']['bytes'], assets['sender_manifest']['sha256']) == FIXED[MANIFEST],
                'sender_manifest_mapping')
        sender_loader = next(row['source'] for row in sender_rows if row['module'] == 'mta_go_deployment')
        require(literal(trees[sender_loader], 'MODULES') == tuple(
                row['module'] for row in sender_rows), 'sender_loader25')
        observer_loader = next(row['source'] for row in assets['observer_sources']
                               if row['module'] == 'mta_go_readonly_loader')
        observer_tree = trees[observer_loader]
        observer_pins = literal(observer_tree, 'SOURCE_PINS')
        require(len(observer_pins) == 38 and literal(observer_tree, 'LOAD_COUNT') == 38 and
                literal(observer_tree, 'READONLY_MANIFEST_SHA') == OBSERVER_SHA, 'observer_loader38')
        mapping = {row['module']: (row['module'], row['bytes'], row['sha256'])
                   for row in assets['observer_sources']}
        require(all(mapping[pin[0]] == pin for pin in observer_pins), 'observer_loader_pin_mapping')
        embedded = base64.b64decode(literal(observer_tree, '_READONLY_MANIFEST_B64'), validate=True)
        require(len(embedded) == 8096 and digest(embedded) == OBSERVER_SHA, 'observer_original_manifest')
        wpa = assets['wpa']
        raw = read(wpa['source'])
        require((len(raw), digest(raw)) == (wpa['bytes'], wpa['sha256']) and
                wpa['mode'] == '0500' and wpa['target'] == assets['sender_root'] + '/native/mta-wpa-supplicant',
                'wpa_original_pin')
        require(raw[:7] == b'\x7fELF\x01\x01\x01' and len(raw) >= 52 and
                struct.unpack_from('<H', raw, 18)[0] == 40 and
                struct.unpack_from('<I', raw, 36)[0] & 0xff000600 == 0x05000400, 'wpa_arm_elf')
        publisher = parse(read(PUBLISHER))
        require(literal(publisher, 'BUNDLE_MANIFEST_SHA') == FIXED[MANIFEST][1] and
                publisher_body(read(PUBLISHER)) == publisher_body(read(PREVIOUS)), 'publisher_only_seal_change')
        report.update(observer_load_count=38, observer_inventory_count=41, baseline_pin_count=4,
            sender_manifest_verified=True, observer_manifest_verified=True, wpa_arm_verified=True,
            publisher_only_seal_change=True, python35_ast_count=len(trees) + 2)
        require(all((BASE / name).read_bytes() == raw and
                    (out / 'private-inputs' / name).read_bytes() == raw
                    for name, raw in snapshots.items()), 'source_changed_during_check')
        report['source_preserved'] = True
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    report['source_count'] = len(snapshots)
    inventory = {name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in snapshots.items()}
    save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    save(out / 'host-exit.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    save(out / 'remote-exit.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'PC SOURCE-only fixed asset audit: original sender25 and Observer41 bytes, '
        b'loader/report38 distinction, actual manifests, pinned WPA ARM ELF and publisher seal. '
        b'Target modules are parsed, not imported or executed. No runtime graph, Owner, '
        b'Parent, Native, ADB, RF, UI, phone, send, receive or restoration acceptance. '
        b'No old test replay. Raw inputs, source paths and errors remain PRIVATE. '
        b'Public ZIP has only result.json and this fixed README.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        require(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
                archive.read('result.json') == result and archive.read('README.txt') == note, 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], source_only=True, result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
