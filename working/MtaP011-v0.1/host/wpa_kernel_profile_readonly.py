"""Fixed kernel-profile diagnostic after namespace ENOENT; default source-only."""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import zipfile
import zlib

BASE = Path(__file__).absolute().parents[1]
FACTS_PIN = 'be59afc4ebda920db84075d509a1dec4e630a70590263eefa5754b9c13a2ad56'
ENTRY = r'''
import sys
if sys.flags.optimize or tuple(sys.version_info[:3])!=(3,5,5) or os.geteuid()!=0 or os.uname()[4]!='armv7l':raise ValueError('platform')
files=ReadFiles(os,time.monotonic,time.monotonic()+10.0)
OWNERS=[files]
before=tuple(sorted(os.listdir('/proc/self/ns')))
config=None;config_errno=0
try:config=files.read('/proc/config.gz',1048576)
except OSError as e:
 if type(e.errno) is not int or e.errno!=2:raise
 config_errno=e.errno
interfaces=tuple(sorted(os.listdir('/sys/class/net')))
after=tuple(sorted(os.listdir('/proc/self/ns')))
count,closed,pending=files.status()
print('RESULT='+repr({'namespace_names_before':before,'namespace_names_after':after,'kernel_release':os.uname()[2],
 'config':config,'config_errno':config_errno,'interfaces':interfaces,'file_count':count,'closed_count':closed,'resource_pending':pending}))
'''


def source_check():
    path = BASE/'host/wpa_daemon_identity_readonly.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FACTS_PIN: raise ValueError('facts_pin')
    module = types.ModuleType('p011_reviewed_facts'); module.__file__ = str(path)
    exec(raw, module.__dict__)
    checks, source = module.source_check()
    if not source.endswith(module.REMOTE_ENTRY): raise ValueError('entry_shape')
    source = source[:-len(module.REMOTE_ENTRY)] + ENTRY
    ast.parse(source, feature_version=(3,5))
    return module, checks, source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly', action='store_true')
    parser.add_argument('--expected-checker-sha256')
    args = parser.parse_args(argv)
    pin = hashlib.sha256(Path(__file__).absolute().read_bytes()).hexdigest()
    if args.execute_readonly != (args.expected_checker_sha256 is not None): parser.error('Explicit execution and exact SHA together')
    module, checks, source = source_check()
    if not args.execute_readonly:
        print(json.dumps({'source_check_pass':True,'checker_sha256':pin,'facts_checker_sha256':FACTS_PIN})); return 0
    if args.expected_checker_sha256 != pin: raise ValueError('reviewed_pin')
    out = module.ROOT/'logs'/('MtaP011-KernelProfileReadOnly-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex())
    out.mkdir(parents=True, exist_ok=False)
    helper = types.ModuleType('p011_reviewed_adb'); helper.__file__ = str(BASE/'host/device_probe.py')
    exec(module._read(BASE/'host/device_probe.py', module.ADB_PIN), helper.__dict__)
    value = module._remote(helper.Adb(out/'private-raw'), source)
    if set(value) != {'namespace_names_before','namespace_names_after','kernel_release','config','config_errno','interfaces','file_count','closed_count','resource_pending'}: raise ValueError('result_shape')
    flags = {}; config = value['config']
    if config is not None:
        decoder = zlib.decompressobj(16+zlib.MAX_WBITS); decoded = decoder.decompress(config,1048577)
        if len(decoded)>1048576 or not decoder.eof or decoder.unused_data: raise ValueError('config_budget')
        lines = decoded.decode('ascii').splitlines()
        for name in ('CONFIG_NAMESPACES','CONFIG_NET_NS','CONFIG_PID_NS','CONFIG_USER_NS','CONFIG_IKCONFIG'):
            matches = [line for line in lines if line.startswith(name+'=') or line=='# '+name+' is not set']
            if len(matches)>1: raise ValueError('config_shape')
            flags[name] = 'not_listed' if not matches else 'n' if matches[0].startswith('#') else matches[0].split('=',1)[1]
    report = {'evidence':'P011_READONLY_KERNEL_PROFILE','checker_sha256':pin,'facts_checker_sha256':FACTS_PIN,
        'pass':value['namespace_names_before']==value['namespace_names_after'] and not value['resource_pending'] and value['file_count']==value['closed_count'],
        'kernel_release':value['kernel_release'],'namespace_names':value['namespace_names_after'],'kernel_flags':flags,
        'config_observed':config is not None,'config_absent':config is None and value['config_errno']==2,
        'wlan_observed':True,'wlan_present':'wlan0' in value['interfaces'],'file_count':value['file_count'],'closed_count':value['closed_count'],
        'device_writes':False,'rf_operations':False,'namespace_authenticated':False,'network_restoration':'NOT_EVALUATED'}
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('Fixed namespace-directory/kernel-config/interface-list diagnostic only.\nNo CLI/socket/RF/config/network/pending write. Raw kernel config and interface names stay private.\nObserved profile is not daemon namespace/reply authentication or network restoration.\n',encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'): bundle.write(out/name,name)
    print(json.dumps(report,indent=2)); print(str(out)); return 0 if report['pass'] else 1


if __name__=='__main__': sys.exit(main())
