"""Explicit normal reboot, once, after reviewed MTA no-residual gates.

Not called from a trial, recovery, START or package. No reset/flash/RF action.
The owner previously authorized normal ADB reboots for device debugging.
"""
import ast
import datetime
import json
from pathlib import Path
import secrets
import time

from device_probe import Adb, ROOT
import device_p2p_v3 as v3

FROZEN=ROOT/'logs/MtaP011-P2pV3Freeze-20261001-021806-f4c9926c/private-candidate'
IDENTITY='eaf5b85a187eb73f'


def main():
    v3.verify_frozen(FROZEN,IDENTITY)
    safety=(FROZEN/'runtime/mta_safety.py').read_text(encoding='utf-8')
    target='/mnt/data/p011-toolbox/candidates/mta-01-'+IDENTITY
    source=v3.probe_source(target,safety,v3.PROBE)
    ast.parse(source,feature_version=(3,5))
    out=ROOT/'logs'/('MtaP011-NormalReboot-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    adb=Adb(out/'private-raw')
    report={'evidence_level':'P011_EXPLICIT_NORMAL_REBOOT','pass':False,'reboot_requests':0,
            'reset_or_flash':False,'rf_trial_started':False,'before_gates_passed':False}
    before=None
    try:
        before=adb.python('before-no-residual',source)
        prior=adb.python('before-prior-journals',v3.probe_source(target,safety,v3.PRIOR_JOURNALS))
        report['before_gates_passed']=v3.preflight_ok(before) and prior.get('clear') is True
        if not report['before_gates_passed']:raise ValueError('Normal reboot preflight failed')
        adb.run('normal-filesystem-sync',['shell','sync'],timeout=15)
        report['reboot_requests']=1
        adb.run('one-normal-adb-reboot',['reboot'],timeout=15)
        adb.run('bounded-wait-device',['wait-for-device'],timeout=45)
        deadline=time.monotonic()+45
        after=None
        while time.monotonic()<deadline:
            try:
                measured=adb.python('readonly-new-boot-gates',source,timeout=12)
                if v3.preflight_ok(measured):after=measured;break
            except Exception:pass
            time.sleep(3)
        if after is None:raise ValueError('Fresh boot gates not ready')
        report['fresh_boot_observed']=before['boot_id']!=after['boot_id']
        report['stock_hashes_unchanged']=before['stock']['hashes']==after['stock']['hashes']
        report['after_gates_passed']=v3.preflight_ok(after)
        report['pass']=all(report.get(k) is True for k in ('fresh_boot_observed','stock_hashes_unchanged','after_gates_passed'))
    except Exception as error:
        report['error_class']=type(error).__name__
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));print('RESULT_DIR='+str(out))
    return 0 if report['pass'] else 1


if __name__=='__main__':raise SystemExit(main())
