"""One PC-only sealed sender UI-v2 source/asset check. No runtime exec.

Only this new combination is checked. Original tests/builders are not run;
AST comparisons reuse the frozen guardian/validator/stop-container evidence.
No UI, Owner, Boot, thread, guardian, RF, native actor or device is started.
"""
import ast
import hashlib
import json
import time
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = 'candidate/formal-send-filecenter-ui-v2/runtime/'
BUNDLE = 'out/mta-ui-send-v2-75ff78ef1ee74591a1a39501'
SESSION = '75ff78ef1ee74591a1a39501'
SOURCE_PINS = (
    (CANDIDATE+'ui_session.py', 29362, 'ea6db0636b68461132ee845abb71c738c5cf81fff53ddbd0a8a98e8b5a2a9cec'),
    (CANDIDATE+'ui_guardian.py', 43994, 'ef9b3881791ff349de830310a39fbefb808db4c86eab7b209434898d5a572247'),
    (CANDIDATE+'ui_assets.py', 12526, '41f071cef365de693a0cb41f44f431e448d26d0e9978a8a6d9d116b1e82f6adb'),
    ('candidate/formal-send-filecenter-ui-v1/runtime/ui_session.py', 26218,
     '86793547830cad7dd74262b0611ea3b0ee63c75441efbe135fdcb687973a6d77'),
    ('candidate/formal-send-filecenter-ui-v1/runtime/ui_guardian.py', 43991,
     '27bb19a168a1ba85001a53a213acbb25f83d9d962ffba4d6ef20b99138a013d9'),
    ('candidate/receive-filecenter-v1/runtime/ui_assets.py', 12509,
     '63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5'),
    ('candidate/formal-send-filecenter-deploy-v3/runtime/formal_send_session.py', 24059,
     '010372da6947869cc4bce3b6ce5471fe36c389bef4ad057981e5f6246a6f519a'),
    ('candidate/formal-send-filecenter-deploy-v3/runtime/mta_client_service_owner.py', 82772,
     '5ebd7843c41df1322e9a408fc659b412ff85421ac049f3f1bf1e019edd5439a5'),
    ('host/build_formal_send_filecenter_ui_v2.py', 16102,
     '48aa97079e455f64914197ad8e87710db392b69b9cbeea52d243e02bb7d9069d'),
)


def need(value, code):
    if value is not True: raise ValueError(code)


def constants(tree):
    result = {}
    def value(node):
        if isinstance(node, ast.Name): return result[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return value(node.left)+value(node.right)
        if isinstance(node, ast.Tuple): return tuple(value(row) for row in node.elts)
        return ast.literal_eval(node)
    for row in tree.body:
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name):
            try: result[row.targets[0].id] = value(row.value)
            except (ValueError, KeyError, TypeError, AttributeError): pass
    return result


def definitions(tree):
    return {row.name: ast.dump(row, include_attributes=False) for row in tree.body
            if isinstance(row, (ast.ClassDef, ast.FunctionDef))}


def main():
    destination = ROOT/'results'/('formal-send-filecenter-ui-v2-source-'+
        time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    report = dict(passed=False, checker_exit=1, child_exit='NOT_RUN', remote_exit='NOT_RUN',
        device_invoked=False, runtime_executed=False, ui_executed=False, native_grant=False,
        radio_admission=False, old_tests=0, old_builder_invoked=False, source_only=True,
        source_pins_verified=False, actual_assets_readback=False,
        guardian_original_definitions_preserved=False, validator_original_definitions_preserved=False,
        original_stop_container_preserved=False, v3_filecenter_source_bound=False,
        sealed_entry_source_connected=False, actual_pure_bytes_method_verified=False,
        pure_bytes_case_sequence=[], inputs=[])
    retained = []
    def read(path, pin=None):
        full = ROOT/path
        need(full.is_file() and not full.is_symlink(), 'input_type')
        raw = full.read_bytes()
        need(len(raw) <= 5*1024*1024, 'input_limit')
        actual = (len(raw), hashlib.sha256(raw).hexdigest())
        if pin is not None: need(actual == pin, 'input_pin')
        (destination/('input-%03d.bin' % len(retained))).write_bytes(raw)
        retained.append((path, raw))
        report['inputs'].append(dict(path=path, bytes=actual[0], sha256=actual[1]))
        return raw
    error_raw = ''
    try:
        trees = [ast.parse(read(path,(size,sha)), feature_version=(3,5))
                 for path,size,sha in SOURCE_PINS]
        ui, guardian, assets, old_ui, old_guardian, old_assets, outer, owner, builder = trees
        u,g,a,o,p,b = (constants(tree) for tree in (ui,guardian,assets,outer,owner,builder))
        need(definitions(guardian) == definitions(old_guardian), 'guardian_business_changed')
        need(definitions(assets) == definitions(old_assets), 'validator_business_changed')
        need(definitions(ui)['_UiScope'] == definitions(old_ui)['_UiScope'], 'stop_scope_changed')
        need(u['SENDER_PIN'] == SOURCE_PINS[6][1:] and
             u['GUARDIAN_PIN'] == SOURCE_PINS[1][1:] and u['ASSETS_PIN'] == SOURCE_PINS[2][1:] and
             u['SENDER_ROOT'] == o['ROOT'] and u['SENDER_PHYSICAL_ROOT'] == o['PHYSICAL_ROOT'] and
             u['SESSION'] == g['SESSION'] == a['SESSION'] == SESSION and
             u['ASSETS'] == g['ASSETS'] == a['REMOTE'] and
             u['CONTROL'] == g['CONTROL'] and g['CANDIDATE'] == u['ASSETS']+'/Z03.mta-ui-candidate' and
             u['SENDER_ASSET_SEAL'] == (SESSION,u['ASSETS'],a['MANIFEST_PIN']), 'identity_chain')
        need(u['FILECENTER_PINS'] == p['FILECENTER_PINS'] and
             sum(row[1] for row in u['FILECENTER_PINS']) == 99972, 'filecenter_owner_pins')
        fc_manifest = json.loads(read('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json'))
        need(tuple((row['module'],row['bytes'],row['sha256']) for row in fc_manifest['sources']) ==
             u['FILECENTER_PINS'], 'filecenter_manifest')
        fc_bytes = tuple((row['module'],read(row['source'],(row['bytes'],row['sha256'])))
                         for row in fc_manifest['sources'])
        # Execute only this new actual pure bytes method, not a runtime graph.
        # No actor/Owner/guardian success is supplied or synthesized here.
        pure_nodes = [row for row in ui.body if isinstance(row,(ast.ClassDef,ast.FunctionDef)) and
                      row.name in ('SenderUiError','_need','_validate_filecenter_sources')]
        need(len(pure_nodes) == 3, 'pure_bytes_definitions')
        pure = {'hashlib':hashlib,'FILECENTER_PINS':u['FILECENTER_PINS']}
        exec(compile(ast.fix_missing_locations(ast.Module(body=pure_nodes,type_ignores=[])),
                     '<actual-pure-fc9-byte-gate>', 'exec'),pure)
        need(pure['_validate_filecenter_sources'](fc_bytes) is fc_bytes, 'positive_9_sources')
        cases = ['positive_9_sources']
        first = fc_bytes[0]
        negatives = (
            ('wrong_count',fc_bytes[:-1],'filecenter_source_shape'),
            ('wrong_length',((first[0],first[1][:-1]),)+fc_bytes[1:],'filecenter_source_pin'),
            ('wrong_hash',((first[0],bytes([first[1][0]^1])+first[1][1:]),)+fc_bytes[1:],'filecenter_source_pin'),
            ('wrong_order',(fc_bytes[1],fc_bytes[0])+fc_bytes[2:],'filecenter_source_pin'),
        )
        for label,rows,code in negatives:
            try: pure['_validate_filecenter_sources'](rows)
            except pure['SenderUiError'] as failure: need(failure.code == code, 'negative_reason')
            else: raise ValueError('negative_accepted')
            cases.append(label)
        stage = json.loads(read(BUNDLE+'/stage-manifest.json'))
        build = json.loads(read(BUNDLE+'/build-result.json'))
        need(stage['session'] == build['session'] == SESSION and
             stage['remote'] == u['ASSETS'] and len(stage['files']) == 19 and
             sum(row['bytes'] for row in stage['files']) == 4182242 <= 4*1024*1024 and
             stage['directories'] == [{'path':path,'mode':'0700'} for path in ('','mta','toolbox')] and
             stage['credentials_in_stage'] is False, 'stage_contract')
        pins = tuple((row['path'],row['bytes'],row['sha256']) for row in stage['files']
                     if row['path'] != 'SOURCE.sha256')
        need(a['PINS'] == pins and a['MANIFEST_PIN'] ==
             (stage['source_manifest']['bytes'],stage['source_manifest']['sha256']), 'validator_stage')
        for row in stage['files']: read(BUNDLE+'/'+row['path'],(row['bytes'],row['sha256']))
        for row in build['inputs']: read(row['path'],(row['bytes'],row['sha256']))
        need(build['builder_sha256'] == SOURCE_PINS[8][2] and build['device_tested'] is False and
             build['resources_verified'] == 400 and build['other_resources_original_bytes'] == 399 and
             build['elf_total_length_unchanged'] is True and build['elf_outside_slot_unchanged'] is True and
             build['old_builder_invoked'] is False, 'build_evidence')
        entry = next(row for row in ui.body if isinstance(row,ast.FunctionDef) and row.name == 'run_fixed')
        need([row.arg for row in entry.args.args] ==
             ['sender_raw','guardian_raw','filecenter_sources','assets_raw','smoke_only'] and
             len(entry.args.defaults) == 1 and ast.literal_eval(entry.args.defaults[0]) is False and
             isinstance(entry.body[-1],ast.Return) and isinstance(entry.body[-1].value,ast.Call) and
             isinstance(entry.body[-1].value.func,ast.Name) and
             entry.body[-1].value.func.id == '_run_prepared', 'sealed_entry')
        create_calls = [row for row in ast.walk(ui) if isinstance(row,ast.Call) and
                        isinstance(row.func,ast.Attribute) and row.func.attr == 'create_filecenter']
        need(len(create_calls) == 1, 'companion_created_once')
        private_names = [row.args[2].value for row in ast.walk(entry) if isinstance(row,ast.Call) and
                         isinstance(row.func,ast.Name) and row.func.id == '_definitions']
        need(len(private_names) == 3 and all(not name.startswith(('mta_','p011_'))
                                           for name in private_names), 'canonical_namespace')
        need(all((ROOT/path).read_bytes() == raw for path,raw in retained), 'input_changed')
        report.update(passed=True,checker_exit=0,source_pins_verified=True,actual_assets_readback=True,
            guardian_original_definitions_preserved=True,validator_original_definitions_preserved=True,
            original_stop_container_preserved=True,v3_filecenter_source_bound=True,
            sealed_entry_source_connected=True,source_preserved=True,files=19,directories=3,
            stage_bytes=4182242,actual_pure_bytes_method_verified=True,pure_bytes_case_sequence=cases,
            entry='run_fixed(sender_raw,guardian_raw,filecenter_sources,assets_raw,smoke_only=False)')
    except BaseException as error:
        report['error_kind'] = type(error).__name__
        error_raw = str(error)+'\n'
    (destination/'stdout.raw').write_bytes(b'')
    (destination/'stderr.raw').write_text(error_raw,encoding='utf-8')
    encoded = (json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme = b'PC SOURCE/asset readback only. No Owner/UI/guardian/native/device execution.\n'
    (destination/'result.json').write_bytes(encoded)
    (destination/'README.txt').write_bytes(readme)
    with zipfile.ZipFile(destination/'safe.zip','w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',encoded); archive.writestr('README.txt',readme)
    print(json.dumps(dict(passed=report['passed'],checker_exit=report['checker_exit'],result=str(destination),
                          error=error_raw.strip(),runtime_executed=False,device_invoked=False)))
    return report['checker_exit']


if __name__ == '__main__':
    raise SystemExit(main())
