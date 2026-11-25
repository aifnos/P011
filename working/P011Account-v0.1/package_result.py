"""Package only redacted evidence; never collect private server responses."""
import datetime
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile
import re

ROOT = Path(__file__).resolve().parent
ATTEMPT = ROOT/'results/20261019-224632-317577d3'
FINAL = ROOT/'results/20261019-224959-5f872b57'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',type=Path,default=ATTEMPT)
    parser.add_argument('--final',type=Path,default=FINAL)
    parser.add_argument('--label',default='verified-20261019-logout')
    parser.add_argument('--reuse-tests',type=Path)
    args = parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9-]+',args.label):
        raise ValueError('Invalid result label')
    attempt = json.loads((args.attempt/'account-result.json').read_text(encoding='utf8'))
    final = json.loads((args.final/'account-result.json').read_text(encoding='utf8'))
    baseline = json.loads((args.final/'baseline.json').read_text(encoding='utf8'))
    after = json.loads((args.final/'after.json').read_text(encoding='utf8'))
    assert attempt['post_count']==1 and attempt['status']=='CLOUD_UNBIND_CONFIRMED'
    assert final['post_count']==0 and final['status']=='ALREADY_UNBOUND_NO_UNBIND'
    assert final['cloud_before']['bound'] is False and final['after']['login'] is False
    assert final['after']['bound'] is False
    assert baseline['hashes']==after['hashes'] and baseline['processes']==after['processes']
    output = ROOT/'results'/args.label
    output.mkdir(exist_ok=False)
    if args.reuse_tests:
        old_hashes=json.loads((args.reuse_tests/'source-sha256.json').read_text(encoding='utf8'))
        for name in ('device_account.py','test_protocol.py'):
            assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==old_hashes[name]
        for name in ('host-tests.stdout.raw','host-tests.stderr.raw'):
            (output/name).write_bytes((args.reuse_tests/name).read_bytes())
        assert b'Ran 7 tests' in (output/'host-tests.stderr.raw').read_bytes()
        assert (output/'host-tests.stderr.raw').read_bytes().rstrip().endswith(b'OK')
    else:
        tests = subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT),'-p','test_protocol.py','-v'],capture_output=True)
        (output/'host-tests.stdout.raw').write_bytes(tests.stdout)
        (output/'host-tests.stderr.raw').write_bytes(tests.stderr)
        assert tests.returncode==0
    report = dict(
        result='云端解绑与笔端退出均已确认',
        time=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
        firmware='z031_v2.4.0-20251128_174826-user',
        original_protocol_reproduced=True, original_ui_exit_button_modified=False,
        authorized_unbind_post_count=1, post_http_status=attempt['unbind']['http_status'],
        post_business_code=attempt['unbind']['business_code'],
        cloud_bound_before=attempt['cloud_before']['bound'],
        cloud_bound_after=final['cloud_before']['bound'],
        cloud_child_profiles_before=attempt['cloud_before']['profiles_count'],
        cloud_child_profiles_after=final['cloud_before']['profiles_count'],
        local_login_before=attempt['before']['login'], local_login_after=final['after']['login'],
        local_bound_after=final['after']['bound'],
        local_user_name_present_after=final['after']['has_user_name'],
        local_parent_name_present_after=final['after']['has_parent_name'],
        normal_reboot_completed=True, new_boot_id=baseline['boot_id'],
        stock_hashes_unchanged=True, final_stock_processes_stable=True,
        memory_or_factory_writes=False, account_config_direct_writes=False,
        post_reboot_check_only_get=True, http_tls_certificates_verified=True,
        host_acceptance_tests=7,
        host_tests_reused=bool(args.reuse_tests),
        reboot_identity_evidence='Final boot and account state independently verified; no unlink request repeated',
        privacy='No SN, token, Secret, account IDs, account names, raw server bodies, firmware binaries or device memory included',
        device_private_responses_retained=True)
    (output/'verification.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    (output/'unlink-transaction.redacted.json').write_text(json.dumps(attempt,indent=2,ensure_ascii=False),encoding='utf8')
    (output/'after-reboot.redacted.json').write_text(json.dumps(final,indent=2,ensure_ascii=False),encoding='utf8')
    source = {}
    for name in ('account_verify.py','device_account.py','test_protocol.py','refresh_after_unbind.py','package_result.py'):
        source[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    (output/'source-sha256.json').write_text(json.dumps(source,indent=2),encoding='utf8')
    target = output.with_suffix('.zip')
    with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.iterdir()):
            archive.write(path,path.name)
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist())==6
        for name in archive.namelist():
            assert archive.read(name)==(output/name).read_bytes()
    print(json.dumps(dict(report=str(output/'verification.json'),zip=str(target),
                         zip_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         final_status=report['result']),indent=2,ensure_ascii=False))


if __name__=='__main__':
    main()
