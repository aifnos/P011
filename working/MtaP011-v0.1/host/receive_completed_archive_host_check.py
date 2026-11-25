"""One bounded NEW HOST administrative-archive MODEL method. Never uses ADB."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_completed_archive.py'
ARCHIVE = 'candidate/receive-completed-archive-v1/runtime/mta_receive_completed_archive.py'
OWNER = 'candidate/receive-completed-archive-v1/runtime/mta_client_service_owner.py'
SELF = 'host/receive_completed_archive_host_check.py'
CMD = 'HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_CHECK.cmd'
INPUTS = (TEST, ARCHIVE, OWNER, SELF, CMD)
PINS = {
    TEST: (22365, '7fe5c8fed450bdda78f1ddfef57eb62106f04e119370e212eafd3af1fb9b631c'),
    ARCHIVE: (41932, 'fef9d58f9d8359e8407500c9d461a1842e52f6e90cf2d670c2c0088a92d888ca'),
    OWNER: (80798, 'f9ef01ed2ecf95b13bba3627e7e810e097f75ed30e8ef470b51a2353fd874bab'),
}
CASES = ('same_inode_complete', 'existing_archive_parent', 'preopen_zero_fd',
    'original_open_error_zero_fd', 'returned_fd_unknown', 'journal_cas_changed',
    'marker_present', 'destination_no_overwrite', 'rename_noreplace_race',
    'postrename_journal_changed', 'destination_fsync_error', 'expiry_closes_known_fds',
    'postrename_expiry_unknown', 'close_failure_no_retry',
    'unsafe_archive_parent_preserved', 'lock_refusal_preserved')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('snapshot_readback')


def main():
    if sys.argv[1:]: raise ValueError('fixed_HOST_only')
    out = BASE / 'results' / ('receive-completed-archive-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources, inventory = {}, {}
    stdout = stderr = b''
    report = dict(schema='p011-receive-completed-archive-host-v1', passed=False,
        host_exit=None, child_exit=None, outer_host_exit_observed=False, remote_exit=None,
        remote_not_run=True, child_timeout_seconds=25, new_methods=1, old_methods=0,
        contracts=0, case_count=0, source_count=0, source_pins_verified=False,
        source_preserved=False, actual_archive_module=True, actual_admin_methods=True,
        actual_production_capture=False, actual_production_originals_consumer=False,
        actual_owner=False, actual_parent=False, actual_finish_receipt=False,
        actual_session_worker=False, actual_session_finalizer=False,
        arm_os_libc_model=True, journal_codec_model=True,
        owner_factory_parent_state_model=True, actual_linux_flock=False,
        actual_arm_rename=False, actual_p011_resources_closed=False,
        device=False, phone=False, rf=False, archive_device_mutation=False,
        historical_client_entries_examined=0, production_admitted=False,
        native_restore_grant=False, restoration_verified=False, error=None)
    try:
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            sources[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
            if name in PINS and (len(raw), digest(raw)) != PINS[name]:
                raise ValueError('fixed_source_pin')
        report['source_count'], report['source_pins_verified'] = len(sources), True
        save(out / 'private-inputs.json',
            (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        try:
            child = subprocess.run([sys.executable, '-I', '-B',
                str(out / 'private-inputs' / TEST),
                'ReceiveCompletedArchiveContracts.test_administrative_io_only'],
                cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
            stdout, stderr, report['child_exit'] = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'timeout'
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
        marks = re.findall(rb'^RECEIVE_COMPLETED_ARCHIVE_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        cases = re.findall(rb'^HOST_RECEIVE_ARCHIVE_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['contracts'] = int(marks[0]) if len(marks) == 1 else 0
        report['case_count'] = len(cases)
        ran = re.findall(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M)
        ok = re.findall(rb'^OK\r?$', stderr, re.M)
        report['passed'] = (report['child_exit'] == 0 and report['error'] is None and
            report['source_pins_verified'] and report['source_preserved'] and
            len(sources) == 5 and len(marks) == 1 and report['contracts'] == 16 and
            tuple(cases) == tuple(name.encode('ascii') for name in CASES) and
            len(ran) == 1 and len(ok) == 1)
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    # These are ORIGINAL child bytes, not normalized stderr-as-success data.
    for name, raw in (('stdout', stdout), ('stderr', stderr)):
        save(out / (name + '.raw'), raw)
        report[name + '_bytes'], report[name + '_sha256'] = len(raw), digest(raw)
    save(out / 'child-exit.raw', (str(report['child_exit']) + '\n').encode('ascii'))
    save(out / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
    report['host_exit'] = 0 if report['passed'] else 1
    save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One NEW HOST MODEL method / 16 subcases; no old tests. The complete fixed '
        b'archive SOURCE runs its actual administrative IO methods: ledger-before-open, '
        b'preopen-zero-FD vs returned-FD-unknown, original-FD close, fixed-root edges, '
        b'flock flags 2|4, journal CAS, ARM382 NOREPLACE contract, inode readback, '
        b'parent fsync, expiry and no retry. OS, ARM, libc, clocks and journal codec are '
        b'explicit isolated models. Only _capture and _check_originals are replaced '
        b'by an explicit Owner/Factory/Parent/State fixture; their actual production '
        b'authentication is NOT tested. Owner SOURCE is pinned/snapshotted, NOT executed. '
        b'No actual Owner, Parent, FinishReceipt, Session worker/finalizer, Linux OFD, '
        b'ARM syscall, Native, RF, P011, phone, CLIENT history, device archive, restoration '
        b'or admission. The production module has no ModelIO injection path. '
        b'Raw stdout/stderr, separate child/host requested exits, NOT_RUN remote and all '
        b'five exact source snapshots remain private. Internal host_exit is the checker '
        b'requested exit, not independently observed outer process evidence. '
        b'Public ZIP contains only this README and the scalar result, never source/raw.\n')
    save(out / 'result.json', result); save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None:
            raise ValueError('zip_members')
        for name, raw in (('result.json', result), ('README.txt', note)):
            value, info = archive.read(name), archive.getinfo(name)
            if (value != raw or info.file_size != len(raw) or
                    info.CRC != zlib.crc32(raw) & 0xffffffff or digest(value) != digest(raw)):
                raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return report['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
