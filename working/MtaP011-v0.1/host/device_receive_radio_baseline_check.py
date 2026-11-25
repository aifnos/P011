"""Explicit P011 readonly execution of the new Bluetooth observer.

The only target write is an exclusive new private diagnostic helper under a
unique volatile directory. No scan/listen/advertisement, Wi-Fi or old pending
mutation. Raw observations contain private bus/peer identity and stay local.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
BINARY = BASE / 'results/receive-radio-baseline-build-20261004-112415-de67547c/mta-bluez-radio-baseline'
BINARY_PIN = (74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181')
PARSER = BASE / 'runtime/mta_receive_radio_baseline.py'
PARSER_PIN = (3971, '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c')
PROBE = BASE / 'host/device_probe.py'
PROBE_PIN = (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')


def fixed(path, pin):
    raw = path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
        raise ValueError('input_identity_changed')
    return raw


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def remote_observer(adb, source):
    # The legacy target shell uses a canonical terminal. Every source line is
    # bounded, and the original alarm is armed BEFORE any stdin read/exec.
    data = (source + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
    if any(len(line) > 512 for line in data.splitlines()):
        raise ValueError('stdin_line_limit')
    command = ('python3 -B -c "import signal,sys;signal.alarm(55);'
        'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-radio-baseline-v1-readonly; '
        'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    raw = adb.run('readonly-observer', ['shell', command], timeout=65, input_data=data)
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = derived.splitlines()
    results = [line[7:] for line in rows if line.startswith('RESULT=')]
    if (rows.count('MTA_REMOTE_OK') != 1 or
            re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M) != ['0'] or len(results) != 1):
        raise RuntimeError('observer_remote_failed')
    return ast.literal_eval(results[0])


REMOTE = r'''
import base64,hashlib,os,stat,subprocess,time
def pending():
 p='/var/volatile/tmp/p011-mta-p2p-device.pending'
 try: s=os.lstat(p)
 except FileNotFoundError:return None
 if not stat.S_ISREG(s.st_mode) or s.st_size>1048576:raise ValueError('pending_unknown')
 fd=os.open(p,0x88000)
 try:
  h=hashlib.sha256(); count=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   count+=len(b)
   if count>1048576:raise ValueError('pending_limit')
   h.update(b)
  a=os.fstat(fd)
 finally:os.close(fd)
 if (s.st_dev,s.st_ino,s.st_size,s.st_mtime)!=(a.st_dev,a.st_ino,a.st_size,a.st_mtime):raise ValueError('pending_changed')
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime,h.hexdigest())
if os.getuid()!=0 or os.path.realpath('/tmp')!='/var/volatile/tmp':raise ValueError('target_profile')
for p in ('/var','/var/volatile','/var/volatile/tmp'):
 s=os.lstat(p)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0:raise ValueError('stage_anchor')
before_pending=pending()
raw=base64.b64decode(PAYLOAD)
if len(raw)!=EXPECTED_BYTES or hashlib.sha256(raw).hexdigest()!=EXPECTED_SHA:raise ValueError('binary_changed')
os.mkdir(STAGE,0o700)
binary=STAGE+'/mta-bluez-radio-baseline'
fd=os.open(binary,1|0x40|0x80|0x88000,0o700)
try:
 at=0
 while at<len(raw):
  n=os.write(fd,raw[at:])
  if n<=0:raise ValueError('stage_short_write')
  at+=n
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size!=len(raw):raise ValueError('stage_identity')
finally:os.close(fd)
rows=[]
for round_number in range(2):
 process=subprocess.Popen([binary,'--capabilities','hci0'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 error=None
 try:
  out,err=process.communicate(timeout=15)
 except subprocess.TimeoutExpired:
  error='observer_timeout';process.kill();out,err=process.communicate(timeout=5)
 finally:
  process.stdout.close();process.stderr.close()
 rows.append({'exit':process.returncode,'stdout':out,'stderr':err,'error':error,
  'pipes_closed':process.stdout.closed and process.stderr.closed,'reaped':process.poll() is not None})
 if error is not None:break
 if round_number==0:time.sleep(.2)
after_pending=pending()
print('RESULT='+repr({'rows':rows,'pending_unchanged':before_pending==after_pending,
 'pending_present':before_pending is not None,'stage_bytes':s.st_size}))
'''


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--check-device', action='store_true')
    opts = args.parse_args()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-radio-baseline-' + ('device-' if opts.check_device else 'source-') + stamp)
    out.mkdir(parents=True)
    report = {'passed': False, 'device_attempted': False, 'device_tested': False, 'observations_valid': False,
        'observations_same': False, 'observer_actors_closed': False, 'limited_stock_unchanged': False,
        'pending_unchanged': None, 'pending_present': None, 'pending_removed': False,
        'rf_mutation_requested': False, 'receive_admission': False, 'receive_tested': False,
        'phone_tested': False, 'full_network_restore_verified': False, 'error': None}
    try:
        binary = fixed(BINARY, BINARY_PIN)
        for path, pin in ((PARSER, PARSER_PIN), (PROBE, PROBE_PIN)):
            fixed(path, pin)
        for path in (BINARY, PARSER, PROBE, Path(__file__).resolve()):
            target = out / 'private-inputs' / path.relative_to(BASE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        if not opts.check_device:
            report['passed'] = True
        else:
            probe = load('_new_radio_device_probe', PROBE)
            radio = load('_new_radio_data_validator', PARSER)
            adb = probe.Adb(out / 'private-raw')
            before = adb.python('before', probe.source())
            if before['stock']['hashes'] != probe.PINS:
                raise ValueError('stock_identity_changed')
            names = ('Z03', 'control_engine', 'weston')
            if not all(sum(row['name'] == name for row in before['stock']['processes']) == 1 for name in names):
                raise ValueError('stock_process_unknown')
            encoded = base64.b64encode(binary).decode('ascii')
            payload = 'PAYLOAD=(\n' + ''.join(repr(encoded[at:at + 128]) + '\n'
                for at in range(0, len(encoded), 128)) + ')\n'
            remote = (payload +
                'STAGE=' + repr('/var/volatile/tmp/p011-mta-radio-baseline-' + stamp) + '\n' +
                'EXPECTED_BYTES=' + repr(BINARY_PIN[0]) + '\nEXPECTED_SHA=' + repr(BINARY_PIN[1]) + '\n' + REMOTE)
            (out / 'target-source-private.py').write_text(remote, encoding='utf-8')
            report['device_attempted'] = True
            actual = remote_observer(adb, remote)
            report['device_tested'] = True
            report['observer_remote_exit'] = 0
            after = adb.python('after', probe.source())
            report['limited_stock_unchanged'] = before['stock'] == after['stock']
            report['pending_unchanged'] = actual['pending_unchanged'] is True
            report['pending_present'] = actual['pending_present'] is True
            rows = actual['rows']
            report['observer_exit_codes'] = [row['exit'] for row in rows]
            report['observer_stderr_bytes'] = [len(row['stderr']) for row in rows]
            report['observer_actors_closed'] = (len(rows) == 2 and
                all(row['pipes_closed'] is True and row['reaped'] is True for row in rows))
            if len(rows) == 2 and all(row['exit'] == 0 and not row['stderr'] and row['error'] is None and
                    0 < len(row['stdout']) <= 4096 for row in rows):
                observations = [json.loads(row['stdout'].decode('utf-8')) for row in rows]
                for observed in observations:
                    radio.normalize(observed)
                report['observations_valid'] = True
                report['observations_same'] = radio.matches(*observations)
                # Public facts only; bus names and Device paths stay private.
                report['connected_device_count'] = len(observations[0]['connected_devices'])
                report['active_instance_count'] = observations[0]['active_instances']
            report['passed'] = all(report[key] is True for key in ('observations_valid',
                'observations_same', 'observer_actors_closed', 'limited_stock_unchanged', 'pending_unchanged'))
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'error-private.txt').write_text(str(error), encoding='utf-8')
    (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text(
        'Two actual P011 readonly BlueZ/MGMT observations only when --check-device is explicit.\n'
        'Exclusive new volatile helper directory retained; old helpers and pending untouched.\n'
        'No scan, listen, advertise, pairing, disconnect, Wi-Fi, stock UI or receive operation.\n'
        'Same DATA and bounded stock check are not full network restoration or phone acceptance.\n'
        'Raw peer identities, bus names, source and diagnostics remain private.\n', encoding='utf-8')
    with zipfile.ZipFile(out / 'public-result.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, ensure_ascii=False))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
