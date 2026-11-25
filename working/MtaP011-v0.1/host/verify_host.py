"""One-click HOST tests + sanitized evidence ZIP. Does not invoke ADB."""
import ast
import datetime
import json
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile

BASE=Path(__file__).resolve().parents[1]


def main():
    out=BASE/'results'/('host-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir(parents=True)
    files=list((BASE/'runtime').glob('*.py'))
    syntax=[]
    for file in files:
        ast.parse(file.read_text(encoding='utf-8'),feature_version=(3,5));syntax.append(file.name)
    # Direct `python host/verify_host.py` starts with host/ on sys.path. Some
    # fixtures import their reviewed siblings through the tests namespace;
    # keep the project root available as well as discover's top-level modules.
    sys.path.insert(0,str(BASE))
    sys.path.insert(0,str(BASE/'tests'))
    tests=unittest.defaultTestLoader.discover(str(BASE/'tests'))
    # Pure RFC codec/state tests are portable and perform no socket/RF writes.
    # POSIX lease/flock tests remain separately recorded on Linux, not faked here.
    codec=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_dhcp.py')
    codec_count=codec.countTestCases();tests.addTests(codec)
    # IP lease codec/transport/static checks are portable. POSIX journal cases
    # explicitly skip on Windows; a separate Linux run must prove those cases.
    owned_ip=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_owned_ip_lease.py')
    owned_ip_count=owned_ip.countTestCases();tests.addTests(owned_ip)
    # Diagnostic-only V6 source/guard comparisons use memory/fake peripherals.
    # This suite does not freeze or execute an RF/IP trial.
    gate_diag=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_send_wifi_v6diag.py')
    gate_diag_count=gate_diag.countTestCases();tests.addTests(gate_diag)
    # Creation-only L3 diagnostics preserve the original accept/reject checks.
    # FakeKernel/MemoryJournal evidence only; no freeze, ADB, RF or IP writes.
    l3_diag=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_send_wifi_v7l3diag.py')
    l3_diag_count=l3_diag.countTestCases();tests.addTests(l3_diag)
    # V8 adds summaries of the same rejected row, not a route permission.
    route_diag=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_send_wifi_v8routediag.py')
    route_diag_count=route_diag.countTestCases();tests.addTests(route_diag)
    # V9 is a functional route-profile exception; these are still HOST fake
    # rows/lease checks, not address installation or a P011 trial.
    mroute=unittest.TestLoader().discover(str(BASE/'native/tests'),pattern='test_send_wifi_v9mroute.py')
    mroute_count=mroute.countTestCases();tests.addTests(mroute)
    with (out/'unittest.txt').open('w',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(tests)
    report={'evidence_level':'HOST_ONLY','tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'skipped':len(result.skipped),'python35_syntax_files':syntax,'pass':result.wasSuccessful(),
            'native_pure_dhcp_codec_tests':codec_count,
            'native_owned_ip_lease_cases':owned_ip_count,
            'native_v6_gate_diagnostic_cases':gate_diag_count,
            'native_v7_l3_diagnostic_cases':l3_diag_count,
            'native_v8_route_diagnostic_cases':route_diag_count,
            'native_v9_mroute_cases':mroute_count,
            'device_runtime':'NOT_EVALUATED','phone_interop':'NOT_TESTED'}
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in ['result.json','unittest.txt']:bundle.write(out/name,name)
    print(json.dumps(report,indent=2));print('RESULT_ZIP='+str(out.with_suffix('.sanitized.zip')))
    return 0 if report['pass'] else 1


if __name__=='__main__':sys.exit(main())
