"""One normal reboot after the explicitly verified account unlink transaction."""
import json
import argparse
import re
import subprocess
import time
from pathlib import Path
from account_verify import Evidence, ADB, stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport',type=int,required=True)
    parser.add_argument('--transaction',type=Path,required=True)
    args = parser.parse_args()
    source = args.transaction.resolve(strict=True)
    if source.name != 'account-result.json' or source.parents[1] != Path(__file__).resolve().parent/'results':
        raise ValueError('Expected a recorded project transaction')
    transaction = json.loads(source.read_text(encoding='utf8'))
    if transaction['post_count'] != 1 or transaction['status'] != 'CLOUD_UNBIND_CONFIRMED':
        raise ValueError('Expected the unique confirmed unlink transaction')
    evidence = Evidence(args.transport)
    print('REFRESH_EVIDENCE='+str(evidence.output),flush=True)
    before = evidence.baseline('before-reboot')
    raw = evidence.command('private-selected-serial',['get-serialno'])
    serial = raw.strip()
    if not re.fullmatch(r'[A-Za-z0-9]+',serial):
        raise ValueError('Unexpected transport serial')
    evidence.command('normal-reboot',['reboot'],timeout=15)
    deadline = time.monotonic()+120
    transport = None
    while time.monotonic()<deadline:
        p = subprocess.run([ADB,'devices','-l'],capture_output=True,timeout=8)
        for line in p.stdout.decode('ascii','replace').splitlines():
            if line.startswith(serial+' ') and re.search(r'\sdevice\s',line):
                match = re.search(r'transport_id:(\d+)',line)
                if match:
                    transport = int(match.group(1))
        if transport is not None:
            p = subprocess.run([ADB,'-t',str(transport),'shell','cat /proc/sys/kernel/random/boot_id'],capture_output=True,timeout=8)
            new_boot = p.stdout.decode('ascii','replace').strip()
            if p.returncode == 0 and new_boot and new_boot != before['boot_id']:
                break
            transport = None
        time.sleep(2)
    if transport is None:
        raise RuntimeError('Device reconnection not confirmed')
    evidence.transport = transport
    time.sleep(12)
    after = evidence.baseline('after-reboot')
    if after['boot_id'] == before['boot_id']:
        raise ValueError('A new boot was not confirmed')
    print('RECONNECTED_TRANSPORT='+str(transport),flush=True)
    stage(evidence,after,'state',False)


if __name__=='__main__':
    main()
