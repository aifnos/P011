"""Review-gated version/config parsing only; no interface/driver/RF arguments.

The fixed official WPA parse-only branch is reviewed in main.c. Two private
synthetic files differ only by update_config=0. No existing config is edited.
Raw stdout/stderr stay private. A successful parse is NOT a GO/interop pass.
"""
import argparse
import datetime
import json
from pathlib import Path
import secrets

from device_probe import Adb, ROOT
from device_p2p_v3 import (PROBE, PRIOR_JOURNALS, preflight_ok, probe_source,
                          verify_frozen)
from device_p2p_v2 import READ_HELPERS

CANDIDATE = "eaf5b85a187eb73f"
FROZEN = ROOT / "logs/MtaP011-P2pV3Freeze-20261001-021806-f4c9926c/private-candidate"

BODY = READ_HELPERS + r'''
stock=stock_snapshot();require_stock(stock)
oldrun=AREA+'/sessions/mta-p2p-v2-20261001-023349-fe630cf7'
private_folder(oldrun)
oldpath=oldrun+'/private.conf';fd=os.open(oldpath,os.O_RDONLY|os.O_NOFOLLOW)
try:
 st=os.fstat(fd)
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>4096:
  raise ValueError('unsafe_synthetic_configuration')
 with os.fdopen(fd,'rb') as handle:
  fd=None;original=handle.read(4097)
finally:
 if fd is not None:os.close(fd)
expected=('ctrl_interface='+oldrun+'/ctrl\nupdate_config=0\np2p_no_group_iface=1\nap_scan=2\n'
 'device_name=P011\ndevice_type=1-0050F204-1\n'
 'driver_param=mta_p2p_initial=1 control_port=0\n').encode('ascii')
if original!=expected or original.count(b'update_config=0\n')!=1:
 raise ValueError('reviewed_synthetic_configuration_changed')
corrected=original.replace(b'update_config=0\n',b'')
owned_directory(RUN,create=True);private_folder(RUN)
binary=TARGET+'/native/mta-wpa-supplicant'
if digest(binary)!=WPA_PIN:raise ValueError('private_binary_pin_mismatch')
raw=[];codes=[]
for label,blob in (('original',original),('corrected',corrected)):
 path=RUN+'/'+label+'.conf'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as handle:handle.write(blob)
 # No -i/-D/-C/-g/-u/-p/-B and no MTA_PRIVATE_P2P environment. The
 # official main() enters wpa_supplicant_parse_config before add_iface.
 process=subprocess.Popen([binary,'-c',path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
 try:output,error=process.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  process.kill();process.communicate();raise ValueError('parse_only_timeout')
 if len(output)>16384 or len(error)>16384:raise ValueError('parse_only_output_limit')
 raw.append({'case':label,'stdout':output,'stderr':error,'remote_exit':process.returncode});codes.append(process.returncode)
process=subprocess.Popen([binary,'-v'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'})
try:output,error=process.communicate(timeout=5)
except subprocess.TimeoutExpired:
 process.kill();process.communicate();raise ValueError('version_only_timeout')
if len(output)>16384 or len(error)>16384:raise ValueError('version_only_output_limit')
raw.append({'case':'version','stdout':output,'stderr':error,'remote_exit':process.returncode})
after=stock_snapshot();require_stock(after)
value={'stock_unchanged':stock==after,'original_config_exit':codes[0],'corrected_config_exit':codes[1],
 'single_directive_removed':original.replace(b'update_config=0\n',b'')==corrected,
 'version_exit':process.returncode,'version_first_line_matches':bool(output.splitlines() and output.splitlines()[0]==b'wpa_supplicant v2.12'),
 'radio_operations':False,'network_configuration':False,'interface_arguments_supplied':False,
 'opt_in_environment_supplied':False,'user_files_accessed':False,'raw_process_outputs':raw}
print('RESULT='+repr(value))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-reviewed", action="store_true")
    args = parser.parse_args()
    if not args.execute_reviewed:
        parser.error("Explicit --execute-reviewed required; importing does nothing")
    identity = verify_frozen(FROZEN, CANDIDATE)
    safety = (FROZEN / "runtime/mta_safety.py").read_text(encoding="utf-8")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    out = ROOT / "logs" / ("MtaP011-WpaConfigNoRf-" + stamp)
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    run = "/mnt/data/p011-toolbox/sessions/mta-config-norf-" + stamp
    adb = Adb(out / "private-raw")
    before = adb.python("before-config-only", probe_source(target, safety, PROBE))
    prior = adb.python("prior-config-only", probe_source(target, safety, PRIOR_JOURNALS))
    if not preflight_ok(before) or prior.get("clear") is not True:
        raise ValueError("Read-only preflight needs review; no parser invoked")
    extra = "RUN=" + repr(run) + "\nTARGET=" + repr(target) + "\n"
    value = adb.python("official-config-parser-only", probe_source(target, safety, BODY, extra))
    after = adb.python("after-config-only", probe_source(target, safety, PROBE))
    report = {k: v for k, v in value.items() if k != "raw_process_outputs"}
    fields = ("stock", "wifi", "network_processes", "interfaces", "boot_id", "route_digest",
              "ipv6_routes_raw", "ipv6_addresses_raw", "ipv6_route_digest", "ipv6_address_digest")
    report.update({"evidence_level": "P011_WPA_CONFIG_PARSE_ONLY", "candidate_identity": identity,
                   "preflight_passed": True, "prior_journals_clear": True,
                   "independent_baseline_unchanged": preflight_ok(after) and all(before.get(k) == after.get(k) for k in fields),
                   "go_formation": "NOT_TESTED", "phone_interop": "NOT_TESTED"})
    report["pass"] = (report["stock_unchanged"] is True and report["independent_baseline_unchanged"] is True and
                      report["original_config_exit"] == 255 and report["corrected_config_exit"] == 0 and
                      report["version_exit"] == 0 and report["version_first_line_matches"] is True and
                      report["single_directive_removed"] is True)
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text("固定官方 WPA 二进制只解析合成配置，有/无 update_config=0 的单变量对照。\n"
                                   "无接口或驱动参数，不广播、不建组、不改网络；不代表互传通过。raw 不进入公开包。\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("RESULT_DIR=" + str(out))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
