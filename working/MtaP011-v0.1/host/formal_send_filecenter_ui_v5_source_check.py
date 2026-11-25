"""New keyboard/message assets and mechanical worker identity SOURCE only.

Reads the actual unique PC build, original single QRC slot and exact source.
Only the pinned pure require/enumerate_qrc definitions are executed. No old
builder main, runtime graph, HOST case, Node/Qt, ADB, RF or device is invoked.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import time
import uuid
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
SESSION = 'a44b98dd639095d9063c9e1a'
BUNDLE = 'out/mta-ui-send-v5-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
RUNTIME = 'candidate/formal-send-filecenter-ui-v5/runtime/'
SOURCES = (
    (RUNTIME + 'ui_session.py', 34436, '817e3452d7da89974190a615f00f93580439071d01ec01a50a6646a46e42438d'),
    (RUNTIME + 'ui_guardian.py', 43993, '3cef000749376d796290b47d48d7cf7557f1954f0a75940d958ffd0c991d9bac'),
    (RUNTIME + 'ui_assets.py', 12526, 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890'),
    ('candidate/formal-send-filecenter-ui-v4/runtime/ui_session.py', 34436, '85e3df1ac5d4dde4120376ecb585ba0c3896531b6e2c101229b57cbd713d36b6'),
    ('candidate/formal-send-filecenter-ui-v4/runtime/ui_guardian.py', 43993, '81812226fcc7f9944fe058e3572d8892069e2e3b827b1c2f66f31fa878562810'),
    ('candidate/formal-send-filecenter-ui-v2/runtime/ui_assets.py', 12526, '41f071cef365de693a0cb41f44f431e448d26d0e9978a8a6d9d116b1e82f6adb'),
    ('host/build_formal_send_filecenter_ui_v5.py', 18604, '6c97c44dd54059eb3b78150bfb2a033aa0a9e8273e900d748df2a0ebca829f49'),
    ('host/build_formal_ui_candidate_v1.py', 11889, '5215ebff474016262900c0599355bfa9b6e48e5960ed0a20f07f17428f87e70c'),
    ('candidate/formal-send-filecenter-deploy-v4/runtime/formal_send_session.py', 24059, 'c64d91da4b3bfc8a6cf74255dc5c367e86a8b99ed6d37b826e9ba0d3c9a80803'),
)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def constants(tree):
    result = {}
    def literal(node):
        if isinstance(node, ast.Name): return result[node.id]
        if isinstance(node, ast.Tuple): return tuple(literal(row) for row in node.elts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return literal(node.left) + literal(node.right)
        return ast.literal_eval(node)
    for row in tree.body:
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name):
            try: result[row.targets[0].id] = literal(row.value)
            except (ValueError, KeyError, TypeError, AttributeError): pass
    return result


def definitions(tree):
    return {row.name: ast.dump(row, include_attributes=False) for row in tree.body
            if isinstance(row, (ast.FunctionDef, ast.ClassDef))}


def main():
    destination = BASE / 'results' / ('formal-send-filecenter-ui-v5-source-' +
        time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    private = destination / 'private-inputs'
    private.mkdir(mode=0o700)
    retained = []
    report = dict(passed=False, checker_exit=1, source_only=True, device_invoked=False,
        runtime_graph_executed=False, old_tests_executed=False, host_cases_executed=False,
        node_invoked=False, qml_invoked=False, adb_invoked=False, radio_invoked=False,
        worker_business_unchanged=False, guardian_business_unchanged=False,
        validator_business_unchanged=False, original_slot_verified=False,
        factory_keyboard_runtime_verified=False, device_ui_verified=False,
        sender_transfer_verified=False, receiver_transfer_verified=False,
        credentials_created=False, inputs=[])

    def read(path, pin=None, project=False):
        full = (PROJECT if project else BASE) / path
        before = full.lstat()
        need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and
             not getattr(before, 'st_file_attributes', 0) & 0x400 and before.st_size <= 5 * 1024 * 1024,
             'input_type')
        raw = full.read_bytes()
        after = full.lstat()
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input_changed')
        actual = (len(raw), sha(raw))
        if pin is not None: need(actual == pin, 'input_pin')
        (private / ('input-%03d.bin' % len(retained))).write_bytes(raw)
        retained.append((full, raw))
        report['inputs'].append(dict(path=path, project_relative=project, bytes=actual[0], sha256=actual[1]))
        return raw

    error = ''
    try:
        raws = [read(path, (length, digest)) for path, length, digest in SOURCES]
        trees = [ast.parse(raw, feature_version=(3, 5)) for raw in raws]
        ui, guardian, assets, old_ui, old_guardian, old_assets, builder, helper, sender = trees
        need(definitions(ui) == definitions(old_ui), 'worker_business_changed')
        need(definitions(guardian) == definitions(old_guardian), 'guardian_business_changed')
        need(definitions(assets) == definitions(old_assets), 'validator_business_changed')
        u, g, a, s = (constants(tree) for tree in (ui, guardian, assets, sender))
        old_u, old_g, old_a = (constants(tree) for tree in (old_ui, old_guardian, old_assets))
        changed_u = {'SESSION', 'GUARDIAN_PIN', 'ASSETS_PIN', 'ASSETS', 'CONTROL_NAME', 'CONTROL', 'SENDER_ASSET_SEAL'}
        changed_g = {'SESSION', 'ASSETS', 'CANDIDATE', 'CONTROL_NAME', 'CONTROL'}
        changed_a = {'SESSION', 'REMOTE', 'MANIFEST_PIN', 'PINS'}
        need({key: value for key, value in u.items() if key not in changed_u} ==
             {key: value for key, value in old_u.items() if key not in changed_u}, 'worker_constants_changed')
        need({key: value for key, value in g.items() if key not in changed_g} ==
             {key: value for key, value in old_g.items() if key not in changed_g}, 'guardian_constants_changed')
        need({key: value for key, value in a.items() if key not in changed_a} ==
             {key: value for key, value in old_a.items() if key not in changed_a}, 'validator_constants_changed')
        need(u['SESSION'] == g['SESSION'] == a['SESSION'] == SESSION and
             u['ASSETS'] == g['ASSETS'] == a['REMOTE'] == REMOTE and u['CONTROL'] == g['CONTROL'] and
             g['CANDIDATE'] == REMOTE + '/Z03.mta-ui-candidate' and
             u['SENDER_PIN'] == SOURCES[8][1:] and u['GUARDIAN_PIN'] == SOURCES[1][1:] and
             u['ASSETS_PIN'] == SOURCES[2][1:] and u['SENDER_ROOT'] == s['ROOT'] and
             u['SENDER_PHYSICAL_ROOT'] == s['PHYSICAL_ROOT'], 'runtime_identity_chain')
        stage = json.loads(read(BUNDLE + '/stage-manifest.json',
            (4227, '80eaec304c785b5fa267f5ae2be49790413293fa49ec392420f8ef18a641f270')))
        build = json.loads(read(BUNDLE + '/build-result.json',
            (6009, '92d940049426d547d8c978c1076c46cca9e88b345214f2f1e41df1d73f6f26f3')))
        need(stage['session'] == build['session'] == SESSION and stage['remote'] == build['remote'] == REMOTE and
             stage['staged_file_count'] == 19 and len(stage['files']) == 19 and
             stage['credentials_in_stage'] is False and stage['independent_receiver_entry_required'] is True,
             'stage_contract')
        pins = tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files'] if row['path'] != 'SOURCE.sha256')
        need(a['PINS'] == pins and a['MANIFEST_PIN'] ==
             (stage['source_manifest']['bytes'], stage['source_manifest']['sha256']) and
             u['SENDER_ASSET_SEAL'] == (SESSION, REMOTE, a['MANIFEST_PIN']), 'asset_seal')
        actual = {row['path']: read(BUNDLE + '/' + row['path'], (row['bytes'], row['sha256'])) for row in stage['files']}
        expected = ''.join(digest + ' ' + str(length) + ' ' + path + '\n' for path, length, digest in pins).encode('ascii')
        need(actual['SOURCE.sha256'] == expected and sum(row['bytes'] for row in stage['files']) < 4 * 1024 * 1024,
             'asset_manifest')
        for row in build['inputs']: read(row['path'], (row['bytes'], row['sha256']))
        need(build['builder_sha256'] == SOURCES[6][2] and build['device_tested'] is False and
             build['factory_keyboard_runtime_verified'] is False and build['original_entry_unchanged'] is True,
             'build_boundary')
        old_bundle = 'out/mta-ui-send-v2-75ff78ef1ee74591a1a39501'
        old_stage = json.loads(read(old_bundle + '/stage-manifest.json',
            (4227, '607334cd01bc23daed14f364b30508d04bd91eaf8974d0d622ce14581fd82cc6')))
        changed_assets = {'Bridge.qml', 'FormalEntry.qml', 'mta/MtaPage.qml', 'SOURCE.sha256', 'Z03.mta-ui-candidate'}
        for row in old_stage['files']:
            if row['path'] not in changed_assets:
                need(actual[row['path']] == read(old_bundle + '/' + row['path'], (row['bytes'], row['sha256'])),
                     'unrelated_asset_changed')
        old_template = read('candidate/formal-send-filecenter-ui-v2/device/FormalEntry.qml',
                            (4019, '798ebacd073769e06045921779fe8d8a765a69f3f2f1a2418cd2d8f2ff731232'))
        new_template = read('candidate/formal-send-filecenter-ui-v5/device/FormalEntry.qml',
                            (4019, '798ebacd073769e06045921779fe8d8a765a69f3f2f1a2418cd2d8f2ff731232'))
        need(old_template == new_template and actual['FormalEntry.qml'] ==
             old_template.replace(b'@REMOTE@', REMOTE.encode('ascii')).replace(b'@SESSION@', SESSION.encode('ascii')),
             'entry_changed')
        original = read('06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
                        (4103844, 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'), True)
        pure = dict(struct=struct, zlib=zlib, QRC_OFFSETS=(0x1a3acc, 0x1a5efc, 0x1a9f54))
        nodes = [row for row in helper.body if isinstance(row, ast.FunctionDef) and row.name in ('require', 'enumerate_qrc')]
        need(len(nodes) == 2, 'pure_qrc_definitions')
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     '<pinned-pure-qrc-enumerator>', 'exec'), pure)
        old_qrc = pure['enumerate_qrc'](original)
        candidate = actual['Z03.mta-ui-candidate']
        new_qrc = pure['enumerate_qrc'](candidate)
        at, slot = 1946708, 1580
        need(len(candidate) == len(original) and candidate[:at] == original[:at] and
             candidate[at + 4 + slot:] == original[at + 4 + slot:] and
             set(old_qrc) == set(new_qrc) and sum(new_qrc[name] == row for name, row in old_qrc.items()
                if name != '/NaviPanel.qml') == 399, 'qrc_original_399')
        compact = ''.join(line.lstrip(' \t') for line in old_qrc['/NaviPanel.qml']['body'].decode('utf-8').splitlines(keepends=True))
        loader = 'Loader { source: "file://' + REMOTE + '/Bridge.qml";onLoaded:{item.navigator=navi;item.factoryKeyboard=vk} }\n'
        expected_nav = compact.replace('id: navi\n', 'id: navi\n' + loader, 1).encode('utf-8')
        need(new_qrc['/NaviPanel.qml']['body'] == expected_nav and
             0 < new_qrc['/NaviPanel.qml']['size'] == build['used_bytes'] <= slot,
             'single_explicit_vk_slot')
        tests = read('tests/test_mta_ui_keyboard_v5.py')
        ast.parse(tests)
        need(all(full.read_bytes() == raw for full, raw in retained), 'source_changed_after_readback')
        report.update(passed=True, checker_exit=0, worker_business_unchanged=True,
            guardian_business_unchanged=True, validator_business_unchanged=True,
            original_slot_verified=True, source_preserved=True, staged_files=19,
            staged_bytes=sum(row['bytes'] for row in stage['files']), used_slot_bytes=build['used_bytes'],
            original_resource_records_unchanged=399, original_formal_entry_unchanged=True,
            unchanged_assets=14, session=SESSION, remote=REMOTE,
            keyboard_scope='original vk only; sceneSource leave and Bridge destruction restore; Qt not tested',
            test_file='tests/test_mta_ui_keyboard_v5.py', affected_host_tests_not_executed=True)
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure) + '\n'
        report['error_kind'] = type(failure).__name__
    raw_report = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    (destination / 'result.json').write_bytes(raw_report)
    (destination / 'stderr.raw').write_text(error, encoding='utf-8')
    (destination / 'README.txt').write_bytes(b'PC SOURCE/immutable asset readback only; no HOST cases, Qt, ADB or RF.\n')
    with zipfile.ZipFile(destination / 'safe.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw_report)
        archive.write(destination / 'README.txt', 'README.txt')
    print(json.dumps(dict(passed=report['passed'], checker_exit=report['checker_exit'],
                         result=str(destination), error=error.strip(), device_invoked=False)))
    return report['checker_exit']


if __name__ == '__main__':
    raise SystemExit(main())
