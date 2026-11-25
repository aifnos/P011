"""One new HOST product method with exact raw exit and input snapshots."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

BASE=Path(__file__).resolve().parents[1]
TEST='tests/test_receive_filecenter_product.py'
ORIGINALS=tuple('integration/ToolboxMta-v0.1/runtime/'+name+'.py' for name in
    ('mta_toolbox_json','mta_toolbox_minhttp','mta_toolbox_storage','mta_toolbox_metrics','mta_toolbox_audio','mta_toolbox_server'))

def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw)!=len(raw):raise OSError('short_write')

def main():
    if sys.argv[1:]:raise ValueError('fixed_HOST_only')
    out=BASE/'results'/('receive-filecenter-product-host-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    out.mkdir(parents=True,exist_ok=False)
    inputs=(TEST,'host/receive_filecenter_product_check.py','HOST_MTA_RECEIVE_FILECENTER_PRODUCT_CHECK.cmd')+ORIGINALS+tuple(
        str(path.relative_to(BASE)).replace('\\','/') for path in sorted((BASE/'candidate/receive-filecenter-v1').rglob('*')) if path.is_file())
    originals={};report=dict(schema='p011-receive-filecenter-product-host-v1',passed=False,
        host_exit=None,error=None,new_methods=1,old_methods=0,device_tested=False,
        phone_tested=False,rf_tested=False,original_owner_tested=False,
        actual_companion_http=True,actual_product_qml=True,mta_endpoint_model=True,
        owner_guard_model=True,host_audio_child=True,audio_pipe_readiness_model=True,physical_media=False,restoration_verified=False)
    try:
        inventory={}
        for name in inputs:
            raw=(BASE/name).read_bytes();originals[name]=raw
            save(out/'private-inputs'/name,raw);inventory[name]=dict(bytes=len(raw),sha256=digest(raw))
        save(out/'private-inputs.json',(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode('ascii'))
        try:
            process=subprocess.run([sys.executable,'-I','-B',str(out/'private-inputs'/TEST)],
                cwd=str(out/'private-inputs'),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=45,check=False)
            stdout,stderr=process.stdout,process.stderr;report['host_exit']=process.returncode
        except subprocess.TimeoutExpired as error:
            stdout,stderr=error.stdout or b'',error.stderr or b'';report['error']='timeout'
        for name,raw in (('stdout',stdout),('stderr',stderr)):
            save(out/(name+'.raw'),raw);report[name+'_bytes']=len(raw);report[name+'_sha256']=digest(raw)
        save(out/'host-exit.raw',(str(report['host_exit'])+'\n').encode('ascii'))
        report['source_count']=len(originals)
        report['source_preserved']=all((BASE/name).read_bytes()==raw and (out/'private-inputs'/name).read_bytes()==raw for name,raw in originals.items())
        marks=re.findall(rb'^RECEIVE_FILECENTER_PRODUCT_CONTRACTS=([0-9]+)\r?$',stdout,re.M)
        report['contracts']=int(marks[0]) if len(marks)==1 else 0
        report['passed']=(report['host_exit']==0 and report['error'] is None and report['source_preserved'] and
            report['contracts']==20 and re.search(rb'^Ran 1 test in [0-9.]+s\r?$',stderr,re.M) is not None and re.search(rb'^OK\r?$',stderr,re.M) is not None)
    except Exception as error:
        report['error']=type(error).__name__;save(out/'private-error.txt',str(error).encode('utf-8'))
    result=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode('ascii')
    note=(b'One new HOST actual QML composition and confined FileCenter loopback test. Original Toolbox FileStore, HTTP parser, audio position reader execute. '
        b'MTA endpoint and Owner guard are explicit models; GST Popen uses a real bounded HOST Python child fixture with modelled pipe readiness. '
        b'Windows held-file rename refusal is observed; Linux rename/symlink race behavior is SOURCE only. '
        b'Qt5.15 Connections deprecation is classified exactly; old Qt5.10-compatible syntax is retained. No sampler is created. '
        b'No original formal Owner/Gate/restore, target FD mode, P011 Qt, physical media, RF or phone acceptance. '
        b'Raw stdout/stderr/exit and immutable inputs stay private. No old tests or pending handling.\n')
    save(out/'result.json',result);save(out/'README.txt',note)
    bundle=out/'public-result.zip'
    with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',result);archive.writestr('README.txt',note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist()!=['result.json','README.txt'] or archive.testzip() is not None or archive.read('result.json')!=result or archive.read('README.txt')!=note:raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'],result_dir=str(out),result_zip=str(bundle),zip_bytes=bundle.stat().st_size,zip_sha256=digest(bundle.read_bytes())),sort_keys=True))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
