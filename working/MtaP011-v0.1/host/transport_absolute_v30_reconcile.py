"""Reconcile exactly two retained successful methods; never execute tests."""
import datetime
import hashlib
import json
from pathlib import Path
import uuid
import zipfile

from transport_absolute_v30_check import BASE, verify, passed_raw, TEST_SHA

ITEMS = (
    ('transport-absolute-v30-bounds-20261002-080427-abfd3936', 'e81fb6ed4d7d6f2c7c2740da7cdfe160a93ae14cdd0d436458c82d317198a2ed'),
    ('transport-absolute-v30-tls-20261002-080429-c3f61ec0', '805a897837c3341947d2fe2b644ac04ea3f009ad1f1dfd6fe3a530fa089e145f'),
)


def main():
    rows, unused = verify()
    reports = []
    for name, pin in ITEMS:
        original = BASE / 'results' / name
        archive = original / 'public-result.zip'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != pin:raise ValueError('original_zip_changed')
        with zipfile.ZipFile(archive) as bundle:
            if bundle.testzip() is not None or set(bundle.namelist()) != {'result.json', 'README.txt'}:
                raise ValueError('original_members_changed')
            if bundle.read('result.json') != (original / 'result.json').read_bytes():raise ValueError('original_projection_changed')
        value = json.loads((original / 'result.json').read_bytes())
        stdout, stderr = ((original / path).read_bytes() for path in ('stdout.raw', 'stderr.raw'))
        if (value['sources'] != rows or value['test_sha256'] != TEST_SHA or value['host_method_passed'] is not False or
                hashlib.sha256(stdout).hexdigest() != value['stdout_sha256'] or
                hashlib.sha256(stderr).hexdigest() != value['stderr_sha256'] or
                not passed_raw(value['host_exit'], value['timeout'], stdout, stderr)):
            raise ValueError('original_method_not_verified')
        output = BASE / 'results' / ('transport-absolute-v30-reconciled-' + value['stage'] + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
        output.mkdir()
        value.update(host_method_passed=True, actual_local_tls_file_method_completed=value['stage']=='tls',
            socketpair_clock_boundary_method_completed=value['stage']=='bounds', public_raw_included=True,
            original_result_zip_sha256=pin, raw_reconciled_without_test_rerun=True,
            correction='only exact pinned HOST TLS-1.2 deprecation warnings excluded from derived unittest shape',
            reconciler_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)+'\n').encode('utf-8')
        note = b'Exact original child exit 0 / OK retained. Only wrapper warning recognition corrected. No test rerun, device, RF or phone. Native CLIENT/F/P011 scope/restore not verified.\n'
        for filename, data in (('result.json',raw), ('README.txt',note), ('stdout.raw',stdout), ('stderr.raw',stderr)):
            (output / filename).write_bytes(data)
        target = output / 'public-result.zip'
        with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as bundle:
            for filename in ('result.json','README.txt','stdout.raw','stderr.raw'):bundle.write(output/filename,filename)
        with zipfile.ZipFile(target) as bundle:
            if bundle.testzip() is not None or bundle.read('stderr.raw') != stderr:raise ValueError('new_archive_changed')
        reports.append(dict(stage=value['stage'], passed=True, tests_rerun=False, result_zip=str(target),zip_sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
    print(json.dumps(reports,ensure_ascii=False))
    return 0


if __name__ == '__main__':raise SystemExit(main())
