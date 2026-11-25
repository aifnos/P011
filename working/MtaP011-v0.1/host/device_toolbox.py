"""Finite real-P011 copied toolbox integration UI check; no RF/user files."""
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zipfile

from device_probe import Adb,BASE,ROOT

SCREEN_NAMES=['01-toolbox-home','02-toolbox-files','03-toolbox-received',
              '04-toolbox-mta','05-toolbox-file-picker','06-toolbox-keyboard',
              '07-toolbox-mta-received','08-toolbox-returned-home']


def snapshot(destination):
    files=[(p,'runtime/'+p.name) for p in sorted((BASE/'runtime').glob('*.py'))]
    files += [(BASE/'runtime'/name,'runtime/'+name) for name in ('MtaTrial.qml','MtaToolboxTrial.qml')]
    files += [(p,'device/'+p.name) for p in sorted((BASE/'device').iterdir()) if p.suffix in ('.qml','.js')]
    files += [(BASE/'out/native'/name,'native/'+name) for name in ('mta-bluez-helper','mta-network-helper')]
    copied=BASE/'integration/ToolboxMta-v0.1'
    for folder in ('runtime','device','web'):
        files += [(p,'integration/ToolboxMta-v0.1/'+folder+'/'+p.name)
                  for p in sorted((copied/folder).iterdir())
                  if p.is_file() and p.suffix in ('.py','.qml','.js','.html','.css','.svg')]
    if not 1<=len(files)<=96:raise ValueError('Candidate member limit')
    manifest=[]
    for path,relative in files:
        if path.is_symlink():raise ValueError('Linked source rejected')
        data=path.read_bytes();output=destination/relative
        output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(data)
        manifest.append('%s %d %s\n'%(hashlib.sha256(data).hexdigest(),len(data),relative))
    raw=''.join(manifest).encode('ascii');(destination/'SOURCE.sha256').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def main():
    sys.path.insert(0,str(BASE/'integration'))
    from verify_integration import verify
    verify()
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S');suffix=secrets.token_hex(4)
    out=ROOT/'logs'/('MtaP011-ToolboxUi-'+stamp+'-'+suffix);out.mkdir(parents=True)
    staging=out/'private-candidate';identity=snapshot(staging)
    safety=(staging/'runtime/mta_safety.py').read_text(encoding='utf-8')
    gate=safety+"\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    target='/mnt/data/p011-toolbox/candidates/mta-01-'+identity
    session='/mnt/data/p011-toolbox/sessions/mta-toolbox-'+stamp+'-'+suffix
    adb=Adb(out/'private-raw');before=adb.python('before',gate)
    after=None;result=None;error=None
    try:
        create=safety+'\np='+repr(target)+"\nowned_directory(p,True)\nprint('RESULT='+repr({'present':bool(os.listdir(p))}))"
        current=adb.python('candidate-directory',create)
        if not current['present']:
            folders=sorted(set(p.parent.relative_to(staging).as_posix() for p in staging.rglob('*') if p.is_file()))
            for folder in folders:
                if folder=='.':continue
                adb.python('candidate-subdir',safety+'\nowned_directory('+repr(target+'/'+folder)+",True)\nprint('RESULT=True')")
            for path in sorted(staging.rglob('*')):
                if path.is_file():adb.run('push-candidate',['push',str(path),target+'/'+path.relative_to(staging).as_posix()])
        check=safety+'\nbase='+repr(target)+'\nverify_candidate(base)\nowned_directory('+repr(session)+',True)\n'
        check+="for name in ('mta-bluez-helper','mta-network-helper'):os.chmod(base+'/native/'+name,0o700)\nprint('RESULT=True')"
        adb.python('verify-candidate',check)
        launch='import sys\nsys.path.insert(0,'+repr(target+'/runtime')+')\n'
        launch+='sys.argv=[\'mta_toolbox_session\',\'--session\','+repr(session)+']\n'
        launch+='import mta_toolbox_session\nr=mta_toolbox_session.main()\nassert r==0\n'
        result=adb.python('finite-toolbox-ui-trial',launch,timeout=95)
    except Exception as caught:
        error=type(caught).__name__;print('TRIAL_ERROR='+error+': '+str(caught))
    finally:
        try:after=adb.python('after-independent',gate)
        except Exception:error=error or 'INDEPENDENT_STOCK_CHECK_FAILED'
        for name in ['result.json','ui.stdout.raw','ui.stderr.raw']+[s+'.png' for s in SCREEN_NAMES]:
            destination=out/'private-session'/name if name.endswith('.raw') or name=='result.json' else out/'screens'/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            try:adb.run('pull-session',['pull',session+'/'+name,str(destination)])
            except Exception:pass
        stored=out/'private-session/result.json'
        if stored.is_file():result=json.loads(stored.read_text(encoding='utf-8'))
    report={'evidence_level':'P011_TOOLBOX_QML_NO_RADIO','candidate_identity':identity,
            'device_ui_result':result,'stock_independent_unchanged':before==after,
            'original_processes_signalled':False,'radio_operations':False,'phone_interop':'NOT_TESTED',
            'screen_scope':'Synthetic Qt item captures, not optical full-device photos',
            'pass':error is None and before==after and bool(result and result.get('pass'))}
    if error:report['error']=error
    report['screens_captured']=sum((out/'screens'/(name+'.png')).is_file() for name in SCREEN_NAMES)
    report['pass']=report['pass'] and report['screens_captured']==len(SCREEN_NAMES)
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('P011 Qt5.10/Wayland新工具箱互传接入有限页面试验。\n两服务同一合成用户目录，不广播/扫描/切网/播放/传用户文件。\n保持原厂文件与进程；截图是Qt内容项，不代表光学全屏或手机互通。\nprivate-*不进入ZIP。',encoding='utf-8')
    archive=out.with_suffix('.sanitized.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
        for name in SCREEN_NAMES:
            path=out/'screens'/(name+'.png')
            if path.is_file():bundle.write(path,'screens/'+path.name)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_DIR='+str(out));print('RESULT_ZIP='+str(archive))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
