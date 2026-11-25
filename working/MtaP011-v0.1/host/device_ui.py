"""Finite P011 Wayland/QML check without Bluetooth or Wi-Fi operations.

Only an immutable candidate and synthetic session files are uploaded. Original
programs remain running. Raw output is private; only result and synthetic
captures enter the public evidence ZIP. A timeout never triggers a restart.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import zipfile

from device_probe import Adb, BASE, ROOT

SCREEN_NAMES = ['01-device-main-no-radio', '02-device-file-selected',
                '03-device-selected-summary', '04-device-keyboard',
                '05-device-received-empty']


def snapshot(destination):
    files = [(p, 'runtime/'+p.name) for p in sorted((BASE/'runtime').glob('*.py'))]
    files += [(BASE/'runtime/MtaTrial.qml', 'runtime/MtaTrial.qml')]
    files += [(p, 'device/'+p.name) for p in sorted((BASE/'device').iterdir())
              if p.suffix in ('.qml', '.js')]
    files += [(BASE/'out/native'/name, 'native/'+name)
              for name in ('mta-bluez-helper', 'mta-network-helper')]
    manifest = []
    for path, relative in files:
        data = path.read_bytes()
        output = destination/relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        manifest.append('%s %d %s\n' % (hashlib.sha256(data).hexdigest(), len(data), relative))
    raw = ''.join(manifest).encode('ascii')
    (destination/'SOURCE.sha256').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def main():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    suffix = secrets.token_hex(4)
    out = ROOT/'logs'/('MtaP011-DeviceUi-'+stamp+'-'+suffix)
    out.mkdir(parents=True)
    staging = out/'private-candidate'
    identity = snapshot(staging)
    safety = (staging/'runtime/mta_safety.py').read_text(encoding='utf-8')
    gate = safety+"\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    target = '/mnt/data/p011-toolbox/candidates/mta-01-'+identity
    session = '/mnt/data/p011-toolbox/sessions/mta-ui-'+stamp+'-'+suffix
    adb = Adb(out/'private-raw')
    before = adb.python('before', gate)
    after = None
    result = None
    error = None
    try:
        create = safety+'\np='+repr(target)+"\nowned_directory(p,True)\n"
        create += "print('RESULT='+repr({'present':bool(os.listdir(p))}))"
        current = adb.python('candidate-directory', create)
        if not current['present']:
            for folder in ('runtime', 'device', 'native'):
                adb.python('candidate-subdir', safety+'\nowned_directory('+repr(target+'/'+folder)+",True)\nprint('RESULT=True')")
            for path in sorted(staging.rglob('*')):
                if path.is_file():
                    adb.run('push-candidate', ['push', str(path), target+'/'+path.relative_to(staging).as_posix()])
        check = safety+'\nbase='+repr(target)+'\nverify_candidate(base)\n'
        check += 'owned_directory('+repr(session)+',True)\n'
        check += "for name in ('mta-bluez-helper','mta-network-helper'):os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        adb.python('verify-candidate', check)
        launch = 'import sys\nsys.path.insert(0,'+repr(target+'/runtime')+')\n'
        launch += 'sys.argv=[\'mta_ui_session\',\'--session\','+repr(session)+']\n'
        launch += 'import mta_ui_session\nr=mta_ui_session.main()\nassert r==0\n'
        result = adb.python('finite-ui-trial', launch, timeout=75)
    except Exception as caught:
        error = type(caught).__name__
        print('TRIAL_ERROR='+error+': '+str(caught))
    finally:
        try:
            after = adb.python('after-independent', gate)
        except Exception:
            error = error or 'INDEPENDENT_STOCK_CHECK_FAILED'
        # Pull exact owned paths only, even when Qt assertions fail.
        for name in ['result.json', 'ui.stdout.raw', 'ui.stderr.raw']+[s+'.png' for s in SCREEN_NAMES]:
            destination = out/'private-session'/name if name.endswith('.raw') or name=='result.json' else out/'screens'/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                adb.run('pull-session', ['pull', session+'/'+name, str(destination)])
            except Exception:
                pass
        stored = out/'private-session/result.json'
        if stored.is_file():
            result = json.loads(stored.read_text(encoding='utf-8'))
    report = {'evidence_level':'P011_QML_NO_RADIO', 'candidate_identity':identity,
              'device_ui_result':result, 'stock_independent_unchanged':before==after,
              'original_processes_signalled':False, 'radio_operations':False,
              'phone_interop':'NOT_TESTED', 'screen_scope':'Synthetic Qt item captures, not an optical full-device photograph',
              'pass':error is None and before==after and bool(result and result.get('pass'))}
    if error: report['error']=error
    report['screens_captured']=sum((out/'screens'/(name+'.png')).is_file() for name in SCREEN_NAMES)
    report['pass']=report['pass'] and report['screens_captured']==len(SCREEN_NAMES)
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('P011 Qt 5.10/Wayland 有限页面试验；保持原厂进程运行。\n仅合成测试目录和截取的Qt内容画面，没有广播、扫描、配对或切换Wi-Fi。\n不代表手机互传或光学全屏验收。private-*不进入脱敏ZIP。',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ['result.json','README.txt']:bundle.write(out/name,name)
        for name in SCREEN_NAMES:
            path=out/'screens'/(name+'.png')
            if path.is_file():bundle.write(path,'screens/'+path.name)
    print(json.dumps(report,ensure_ascii=False,indent=2))
    print('RESULT_DIR='+str(out));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
