"""Fixed new callback method only, original byte logs and snapshots."""
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
TEST='tests/test_receive_filecenter_audio_callback.py'
INPUTS=(TEST,'host/receive_filecenter_audio_callback_check.py','HOST_MTA_RECEIVE_AUDIO_CALLBACK_CHECK.cmd')+tuple(
 'candidate/receive-filecenter-v1/device/toolbox/'+name for name in ('FilesPage.qml','Theme.js','Button.qml','Label.qml','VideoPane.qml'))
def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as handle:
  if handle.write(raw)!=len(raw):raise OSError('short_write')
def main():
 if sys.argv[1:]:raise ValueError('fixed_HOST_only')
 out=BASE/'results'/('receive-filecenter-audio-callback-host-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8]);out.mkdir(parents=True,exist_ok=False)
 sources={};report=dict(schema='p011-filecenter-audio-callback-host-v1',passed=False,host_exit=None,error=None,
  new_methods=1,old_methods=0,actual_qml=True,http_model=True,device_tested=False,physical_audio=False)
 try:
  inventory={}
  for name in INPUTS:
   raw=(BASE/name).read_bytes();sources[name]=raw;save(out/'private-inputs'/name,raw);inventory[name]=dict(bytes=len(raw),sha256=digest(raw))
  save(out/'private-inputs.json',(json.dumps(inventory,indent=2,sort_keys=True)+'\n').encode('ascii'))
  try:
   child=subprocess.run([sys.executable,'-I','-B',str(out/'private-inputs'/TEST)],cwd=str(out/'private-inputs'),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25,check=False)
   stdout,stderr=child.stdout,child.stderr;report['host_exit']=child.returncode
  except subprocess.TimeoutExpired as error:stdout,stderr=error.stdout or b'',error.stderr or b'';report['error']='timeout'
  for name,raw in (('stdout',stdout),('stderr',stderr)):save(out/(name+'.raw'),raw);report[name+'_bytes']=len(raw);report[name+'_sha256']=digest(raw)
  save(out/'host-exit.raw',(str(report['host_exit'])+'\n').encode('ascii'))
  report['source_count']=len(sources);report['source_preserved']=all((BASE/name).read_bytes()==raw and (out/'private-inputs'/name).read_bytes()==raw for name,raw in sources.items())
  marks=re.findall(rb'^RECEIVE_FILECENTER_AUDIO_CALLBACK_CONTRACTS=([0-9]+)\r?$',stdout,re.M);report['contracts']=int(marks[0]) if len(marks)==1 else 0
  report['passed']=report['host_exit']==0 and report['error'] is None and report['source_preserved'] and report['contracts']==3 and re.search(rb'^Ran 1 test in [0-9.]+s\r?$',stderr,re.M) is not None and re.search(rb'^OK\r?$',stderr,re.M) is not None
 except Exception as error:report['error']=type(error).__name__;save(out/'private-error.txt',str(error).encode('utf-8'))
 result=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
 note=b'One new actual HOST-QML method for audio callback command/open-generation/path tickets. Delayed in-memory request callbacks; no HTTP/audio process/phone/P011/restore acceptance. Old passed product method is not executed. Raw logs and inputs stay private.\n'
 save(out/'result.json',result);save(out/'README.txt',note);bundle=out/'public-result.zip'
 with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED) as archive:archive.writestr('result.json',result);archive.writestr('README.txt',note)
 with zipfile.ZipFile(bundle) as archive:
  if archive.namelist()!=['result.json','README.txt'] or archive.testzip() is not None or archive.read('result.json')!=result or archive.read('README.txt')!=note:raise ValueError('zip_readback')
 print(json.dumps(dict(passed=report['passed'],result_dir=str(out),zip_bytes=bundle.stat().st_size,zip_sha256=digest(bundle.read_bytes())),sort_keys=True));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
