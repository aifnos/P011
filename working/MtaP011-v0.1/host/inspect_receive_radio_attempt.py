"""Readonly inspection of the one failed observer-stdin attempt; no cleanup."""
import datetime
import importlib.util
from pathlib import Path
import uuid

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fixed_radio_probe', str(BASE / 'host/device_probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
out = BASE / 'results' / ('receive-radio-attempt-inspection-' +
    datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
out.mkdir(parents=True)
adb = probe.Adb(out / 'private-raw')
actual = adb.python('inspect', r'''
import os
stage='/var/volatile/tmp/p011-mta-radio-baseline-20261004-112924-7593e31b'
rows=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 try:
  argv=open('/proc/'+pid+'/cmdline','rb').read(4096)
  if b'mta-readonly-probe' not in argv and b'p011-mta-radio-baseline' not in argv:continue
  rows.append({'pid':int(pid),'argv':argv,'stat':open('/proc/'+pid+'/stat').read(4096),
   'exe':os.readlink('/proc/'+pid+'/exe')})
 except (OSError,ValueError):pass
print('RESULT='+repr({'stage_present':os.path.lexists(stage),'rows':rows}))
''')
print('STAGE_PRESENT=' + str(actual['stage_present']))
print('MATCHED_DIAGNOSTIC_PROCESSES=' + str(len(actual['rows'])))
print('RESULT_DIR=' + str(out))
