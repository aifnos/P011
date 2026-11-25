"""Explicit Python UDP API introspection, without creating any UDP socket."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import zipfile
from device_probe import Adb, BASE, ROOT
from device_ip_readonly import V4_TARGET, V4_MANIFEST_SHA256, _baseline_equal
from device_p2p_v2 import PROBE, preflight_ok
from device_p2p_v4 import probe_source

BODY = r'''
import socket,sys
require_stock(stock_snapshot())
if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('readonly_target')
if digest(BASE+'/SOURCE.sha256')!=REFERENCE_PIN:raise ValueError('readonly_reference_pin')
result={'recvmsg_api':callable(getattr(socket.socket,'recvmsg',None)),
 'sendmsg_api':callable(getattr(socket.socket,'sendmsg',None)),
 'cmsg_space_api':callable(getattr(socket,'CMSG_SPACE',None)),
 'bindtodevice_constant':getattr(socket,'SO_BINDTODEVICE',None)==25,
 'broadcast_constant':getattr(socket,'SO_BROADCAST',None)==6,
 'truncation_constants':getattr(socket,'MSG_TRUNC',None)==32 and getattr(socket,'MSG_CTRUNC',None)==8,
 'ipv4_pktinfo_constant_exposed':getattr(socket,'IP_PKTINFO',None)==8,
 'ipv4_family_constant':getattr(socket,'AF_INET',None)==2,
 'socket_created':False,'radio_operations':False,'network_configuration':False}
print('RESULT='+repr(result))
'''
FIELDS = frozenset(('recvmsg_api','sendmsg_api','cmsg_space_api','bindtodevice_constant',
 'broadcast_constant','truncation_constants','ipv4_pktinfo_constant_exposed',
 'ipv4_family_constant','socket_created','radio_operations','network_configuration'))


def run():
    safety = (BASE/'runtime/mta_safety.py').read_text(encoding='utf-8')
    if hashlib.sha256(safety.encode('utf-8')).hexdigest() != '03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81':
        raise ValueError('Safety source pin')
    out = ROOT/'logs'/('MtaP011-UdpApiReadOnly-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True,exist_ok=False)
    report = {'evidence_level':'P011_UDP_PYTHON_API_READONLY','pass':False,
      'checker_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'actual_udp_bind':'NOT_TESTED','dhcp_exchange':'NOT_TESTED','phone_interop':'NOT_TESTED'}
    adb = Adb(out/'private-raw'); before = after = None
    try:
        before = adb.python('before-udp-api',probe_source(V4_TARGET,safety,PROBE))
        if not preflight_ok(before):raise ValueError('Readonly preflight')
        extra = 'BASE='+repr(V4_TARGET)+'\nREFERENCE_PIN='+repr(V4_MANIFEST_SHA256)+'\n'
        source = probe_source(V4_TARGET,safety,BODY,extra)
        ast.parse(source,feature_version=(3,5))
        value = adb.python('udp-api-introspection-only',source)
        if type(value) is not dict or set(value)!=FIELDS or any(type(v) is not bool for v in value.values()):
            raise ValueError('Readonly fixed schema')
        if any(value[k] for k in ('socket_created','radio_operations','network_configuration')):
            raise ValueError('Readonly boundary')
        report.update(value)
    except Exception:
        report['host_or_parse_error']=True
    finally:
        try:after=adb.python('after-udp-api',probe_source(V4_TARGET,safety,PROBE))
        except Exception:report['after_check_failed']=True
    report['independent_baseline_unchanged']=bool(before and after and _baseline_equal(before,after))
    report['pass']=bool(FIELDS<=set(report) and report['independent_baseline_unchanged'] and 'host_or_parse_error' not in report)
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('Python 3.5 socket API/constant introspection only; no UDP socket created.\n'
      'A missing IP_PKTINFO constant can be explicitly defined as Linux UAPI 8; kernel acceptance remains NOT_TESTED.\n'
      'Before/after original stock/process/Wi-Fi/interface/main IPv4 route/full IPv6 baseline compared.\n'
      'Actual UDP bind, ingress/source binding, DHCP, association and PHONE are NOT_TESTED. Raw logs remain private.\n',encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    print(json.dumps(report,indent=2));print('RESULT_DIRECTORY='+str(out))
    return 0 if report['pass'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-readonly',action='store_true',required=True)
    parser.parse_args()
    raise SystemExit(run())
