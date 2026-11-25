"""Affected v4 source composition only; no old suites, graph or device runs."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
OLD = 'candidate/formal-send-filecenter-deploy-v3/'
NEW = 'candidate/formal-send-filecenter-deploy-v4/'
UIOLD = 'candidate/formal-send-filecenter-ui-v3/runtime/'
UINEW = 'candidate/formal-send-filecenter-ui-v4/runtime/'
DOMAIN_OLD = 'p011-mta-formal-send-filecenter-deploy-v3'
DOMAIN_NEW = 'p011-mta-formal-send-filecenter-deploy-v4'
OBS_OLD = 'p011-mta-go-observer-v85'
OBS_NEW = 'p011-mta-go-observer-libc-v1'
PINS = (
    (NEW+'assets/ordinary-source-manifest.json',20642,'5cd52fe1b7a11103a7675f1250691b1aaa42de93ed15ca22f0a7b30d1ff43125'),
    (NEW+'assets/asset-sources.json',24267,'be76740f8d7283e2db5806790c87997dee24a0911beb1306d7c9833086745ec0'),
    (OLD+'assets/ordinary-source-manifest.json',20141,'e95505b409652150330dbba282cd038c02d978d04378f250310219a71305f37a'),
    (OLD+'assets/asset-sources.json',23850,'3551b5e546aa27e6d68e664b787ffd500e3992fd6f4d93bc7dc28291021c22fa'),
    ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json',15861,
     '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a'),
    ('candidate/go-observer-libc-v1/runtime/mta_go_readonly_parent.py',52881,
     'a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6'),
    (OLD+'assets/filecenter-source-manifest.json',2466,'14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d'),
    (NEW+'runtime/mta_send_trial.py',22052,'a534244c0e1925916aea4d10348ebc6bbe2577032cfd10bcc7bca9f4fa3ab1f3'),
    (NEW+'runtime/mta_send_terminal_consumer.py',12785,'466e01d318b2d525e71d30a51721b5cb4e9cbc80becc932db37d60511eee19dd'),
    (NEW+'runtime/mta_service.py',145540,'baaa91b8e0b22435da5d524d20d6425e80e131a124b1b308009c942d024571cb'),
    (NEW+'runtime/mta_go_readonly_terminal_parent.py',66981,'ba34d2442ded555d7f7ab1166b9ffd703a1e59f2aa484c20a6226a428e49e823'),
    (NEW+'runtime/mta_client_receive_boot.py',19583,'4aeffe569138a8f364b377f746a9e80f29cb246e514dd103f3753eca65120a6e'),
    (NEW+'runtime/mta_client_service_owner.py',82944,'cfdadf74b81b435d2661d3f4e0b1debc25bfa791bfb03d2f966a0f911e12aea8'),
    (NEW+'runtime/formal_send_session.py',24059,'c64d91da4b3bfc8a6cf74255dc5c367e86a8b99ed6d37b826e9ba0d3c9a80803'),
    (UIOLD+'ui_session.py',34436,'15d4a09b7675e4d1234f8ad8941bac6b2543c385491b795552358dea0e9f6aae'),
    (UIOLD+'ui_guardian.py',43993,'053f99e012cfd2dbc85bd9d23b01abb9b43e152918b8d6c78325cc6adc8f99fd'),
    (UINEW+'ui_session.py',34436,'85e3df1ac5d4dde4120376ecb585ba0c3896531b6e2c101229b57cbd713d36b6'),
    (UINEW+'ui_guardian.py',43993,'81812226fcc7f9944fe058e3572d8892069e2e3b827b1c2f66f31fa878562810'),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value):
    if not value:
        raise ValueError('affected_source_contract')


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        need(f.write(raw) == len(raw))
    need(path.read_bytes() == raw)


def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3,5))
    nodes = [n.value for n in tree.body if isinstance(n,ast.Assign) and
        any(isinstance(t,ast.Name) and t.id == name for t in n.targets)]
    need(len(nodes) == 1)
    return ast.literal_eval(nodes[0])


def read(inputs, row):
    path,size,sha = row
    raw = (BASE/path).read_bytes()
    need((len(raw),digest(raw)) == (size,sha))
    inputs[path] = raw
    return raw


def verify(inputs):
    for row in PINS:
        read(inputs,row)
    old = json.loads(inputs[OLD+'assets/ordinary-source-manifest.json'])
    new = json.loads(inputs[NEW+'assets/ordinary-source-manifest.json'])
    assets_old = json.loads(inputs[OLD+'assets/asset-sources.json'])
    assets_new = json.loads(inputs[NEW+'assets/asset-sources.json'])
    observer = json.loads(inputs['candidate/go-observer-libc-v1/assets/observer-source-catalog.json'])
    need(new['source_count'] == len(new['sources']) == 32 and new['ordinary_source_bytes'] == 1078108 and
         sum(r['bytes'] for r in new['sources']) == 1078108 and new['ordinary_batch_bytes'] == 1346543)
    old_roles = {r['module']:r for r in old['sources']+old['startup_sources']}
    new_roles = {r['module']:r for r in new['sources']+new['startup_sources']}
    need(tuple(r['module'] for r in new['sources']) == tuple(r['module'] for r in old['sources']))
    changed = set(new['ordinary_changed_roles'])
    need(changed == {'mta_go_readonly_parent','mta_go_readonly_terminal_parent','mta_send_trial',
                     'mta_send_terminal_consumer','mta_service'})
    for name,row in new_roles.items():
        previous = old_roles[name]
        if name not in changed and name not in ('mta_client_receive_boot','mta_client_service_owner','formal_send_session'):
            need((row['source'],row['bytes'],row['sha256']) ==
                 (previous['source'],previous['bytes'],previous['sha256']))
        need(row['target'] == previous['target'].replace(DOMAIN_OLD,DOMAIN_NEW) and
             row['physical_target'] == previous['physical_target'].replace(DOMAIN_OLD,DOMAIN_NEW))
    for key in ('sender_sources','wpa','sender_manifest','sender_root','sender_source_count','sender_source_bytes'):
        need(assets_new[key] == assets_old[key])
    need(assets_new['observer_root'] == observer['root'] and assets_new['observer_source_bytes'] == 1442508)
    expected_observer = [(r['module'],r['source'],r['target'],r['bytes'],r['sha256']) for r in observer['files']]
    need([(r['module'],r['source'],r['target'],r['bytes'],r['sha256']) for r in assets_new['observer_sources']] == expected_observer)
    for name in ('mta_send_trial','mta_send_terminal_consumer','mta_service',
                 'mta_go_readonly_terminal_parent','mta_client_receive_boot','mta_client_service_owner','formal_send_session'):
        previous = old_roles[name]
        old_raw = read(inputs,(previous['source'],previous['bytes'],previous['sha256']))
        row = new_roles[name]
        raw = inputs[row['source']]
        restored = raw.decode('utf-8').replace(DOMAIN_NEW,DOMAIN_OLD).replace(OBS_NEW,OBS_OLD)
        # Reverse only the actual role/startup pins; complete bytes otherwise must
        # match old production. No function is executed, no scope/cap is modeled.
        for role,updated in new_roles.items():
            saved = old_roles[role]
            if updated['bytes'] != saved['bytes'] or updated['sha256'] != saved['sha256']:
                restored = restored.replace(str(updated['bytes'])+", '"+updated['sha256']+"'",
                    str(saved['bytes'])+", '"+saved['sha256']+"'")
        for updated,saved in zip(assets_new['observer_sources'],assets_old['observer_sources']):
            restored = restored.replace(str(updated['bytes'])+", '"+updated['sha256']+"'",
                str(saved['bytes'])+", '"+saved['sha256']+"'")
            restored = restored.replace(str(updated['bytes'])+",\n             '"+updated['sha256']+"'",
                str(saved['bytes'])+",\n             '"+saved['sha256']+"'")
        need(restored.encode('utf-8') == old_raw)
        ast.parse(raw.decode('utf-8'),feature_version=(3,5))
    boot = inputs[NEW+'runtime/mta_client_receive_boot.py']
    need(literal(boot,'SOURCE_PINS') == tuple((r['module'],r['bytes'],r['sha256']) for r in new['sources']) and
         literal(boot,'LOAD_SECONDS') == 10.0 and literal(boot,'GO_ASSET_ROOT') == assets_old['sender_root'])
    owner = inputs[NEW+'runtime/mta_client_service_owner.py']
    expected_assets = tuple((r['target'],r['bytes'],r['sha256'],0o400) for r in
                           assets_new['sender_sources']+assets_new['observer_sources'])
    need(literal(owner,'FIXED_ASSET_PINS')[:66] == expected_assets)
    fc = json.loads(inputs[OLD+'assets/filecenter-source-manifest.json'])
    need(literal(owner,'FILECENTER_PINS') == tuple((r['module'],r['bytes'],r['sha256']) for r in fc['sources']) and
         fc['source_bytes'] == 99972 and fc['parent_deadline_crop_integrated'] is True)
    for name in ('ui_guardian','ui_session'):
        raw = inputs[UINEW+name+'.py']
        restored = raw.decode('ascii').replace(DOMAIN_NEW,DOMAIN_OLD).replace('formal-send-filecenter-ui-v4','formal-send-filecenter-ui-v3')
        restored = restored.replace('sender-ui-diagnostic-v4','sender-ui-diagnostic-v3').replace('SOURCE_FORMAL_SEND_FILECENTER_UI_V4','SOURCE_FORMAL_SEND_FILECENTER_UI_V3')
        for current,previous in ((new_roles['formal_send_session'],old_roles['formal_send_session']),
            ({'bytes':43993,'sha256':PINS[-1][2]},{'bytes':43993,'sha256':PINS[-3][2]})):
            restored = restored.replace(str(current['bytes'])+", '"+current['sha256']+"'",
                str(previous['bytes'])+", '"+previous['sha256']+"'")
        need(restored.encode('ascii') == inputs[UIOLD+name+'.py'])
        ast.parse(raw.decode('ascii'),feature_version=(3,5))
    ui = inputs[UINEW+'ui_session.py']
    need(literal(ui,'SENDER_PIN') == (new_roles['formal_send_session']['bytes'],new_roles['formal_send_session']['sha256']) and
         literal(ui,'GUARDIAN_PIN') == PINS[-1][1:] and
         literal(ui,'ASSETS_PIN') == (12526,'41f071cef365de693a0cb41f44f431e448d26d0e9978a8a6d9d116b1e82f6adb'))
    need(new['runtime'] is False and new['native'] is False and new['rf'] is False and new['phone'] is False)


def main():
    import sys
    if len(sys.argv) != 1:
        return 2
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)
    out=BASE/'results'/('formal-send-observer-libc-v4-source-'+stamp)
    out.mkdir(parents=True,exist_ok=False)
    inputs={}
    report=dict(kind='formal-send-observer-libc-v4-affected-source',passed=False,
        source_preserved=False,input_count=0,error_kind=None,ordinary_roles=32,changed_ordinary_roles=5,
        ordinary_batch_files=37,ordinary_batch_bytes=1346543,observer_root_isolated=True,
        sender_source_reused=True,old_suite_run=0,graph_executed=False,ui_executed=False,
        device_invoked=False,rf_requested=False,native_grant=False,full_owner_ui_verified=False,
        ui_rebuilt=False,source_diffs_only=False)
    try:
        verify(inputs)
        report['source_diffs_only']=True
        report['passed']=True
    except BaseException as error:
        report['error_kind']=type(error).__name__
    inventory={};preserved=bool(inputs)
    for path,raw in inputs.items():
        write_new(out/'private-inputs'/path,raw)
        inventory[path]=dict(bytes=len(raw),sha256=digest(raw))
        preserved=preserved and (BASE/path).read_bytes()==raw
    report['source_preserved'],report['input_count']=preserved,len(inputs)
    report['passed']=report['passed'] and preserved
    write_new(out/'private-inputs.json',(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode('ascii'))
    result=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=(b'Affected v4 byte-pin/AST composition only; no old suites or graph/device execution.\n'
        b'Exact inverse narrow source edits verify unchanged business, refusal, cleanup and caps.\n'
        b'Ordinary v4 is isolated; sender v3 assets and existing 19 UI assets are reused.\n'
        b'Observer Parent actual child PASS is not whole v4 Owner/UI or phone acceptance.\n'
        b'No deployment, pending/history repair, RF, credentials or Native/restore grant.\n')
    write_new(out/'result.json',result);write_new(out/'README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip','x',zipfile.ZIP_DEFLATED) as z:
        z.writestr('result.json',result);z.writestr('README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip') as z:
        need(z.namelist()==['result.json','README.txt'] and z.testzip() is None and
             z.read('result.json')==result and z.read('README.txt')==readme)
    print(json.dumps(dict(passed=report['passed'],result_dir=str(out)),sort_keys=True))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
