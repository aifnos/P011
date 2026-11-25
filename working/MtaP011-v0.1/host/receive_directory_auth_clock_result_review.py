"""Offline review of one preserved Windows-CRLF result; never rerun code.

Reads fixed artifacts/snapshots only. The old checker FAIL remains unchanged.
The later exact LF/CRLF harness correction has not been executed by this tool.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = 'results/receive-directory-auth-clock-host-20261003-202947-864e80c5'
CHECKER = 'host/receive_directory_auth_clock_check.py'
ARTIFACTS = (
    ('result.json', 2408, '9ce661894fbe2dfc8f8bbedec5725b93e0ff17919914dffb5900b1999e195b03'),
    ('stdout.raw', 137, '7c9ad7552f7bac38bb663b1f09ad1bd856e7e0129b7ddd7a57285af0bcc0e396'),
    ('stderr.raw', 103, '7ed4961b42fd336ff479a6767e1cdbf0867e5fc340039019fd0807db0cf5a3e4'),
    ('README.txt', 402, '570489890d590dbd28384a09b65e52ba4676e1dfbb7541e0f479b7f941812e5e'),
    ('public-result.zip', 1531, '93d440c2dcb5e3c6ba054f67792f927ad97ed3551e73c8dd7110e7a6d52c481c'),
)
INPUTS = (
    ('tests/test_receive_directory_auth_clock.py', 10289, 'ff1fddbd26d966278aaa466034949d71546f555bfd6f238ae770c469c7aab7a1'),
    ('candidate/receive-directory-auth-clock-v2/runtime/mta_client_executor.py', 114074, '01dfd6295f2ac06464e7d7b0de1d99aa1ec97bef25f95222efa346609f25ecfb'),
    ('runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('runtime/mta_protocol.py', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('candidate/client-integrated-v37/runtime/mta_client_control_frame.py', 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    (CHECKER, 5479, '0398175f7dc0fdc0298efef3992819d378d9637929e03dbbafa34af499bc6540'),
    ('HOST_MTA_RECEIVE_DIRECTORY_AUTH_CLOCK_CHECK.cmd', 103, '4b4f54e22009062f113b3be17b04e1cabe1c8814b6f774efe8d7a146e05ccdc8'),
)
FUTURE_CHECKER_PIN = (5513, '156e4420e9f0f03776d81ae2a911a4d709a8227b0ba35e30fbb495ee5fb998c7')
OLD_LINE = b'    passed = code == 0 and not timed_out and unchanged and stdout == MARKER and summary_ok\n'
NEW_LINE = b"    passed = code == 0 and not timed_out and unchanged and stdout in (MARKER, MARKER.replace(b'\\n', b'\\r\\n')) and summary_ok\n"
WINDOWS_MARKER = (b'HOST_RECEIVE_DIRECTORY_AUTH_CLOCK new_methods=1 old_methods=0 cases=4 '
    b'filesystem_model=true binding_model=true device=false phone=false\r\n')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, size, digest, retained):
    raw = path.read_bytes()
    retained[path] = raw
    if len(raw) != size or _sha(raw) != digest:
        raise ValueError('fixed_original_changed')
    return raw


def _verify():
    original = BASE / ORIGINAL
    retained = {}
    raw = {name: _read(original / name, size, digest, retained) for name, size, digest in ARTIFACTS}
    expected = dict(schema='receive-directory-auth-clock-host-v2', passed=False,
        child_exit=0, timeout=False, child_invocations=1, new_methods=1, old_methods=0,
        completed_domains=None, source_snapshots_equal=True, target_python35_ast_sources=1,
        target_ast_path=INPUTS[1][0], snapshot_count=7, actual_F_authentication_tested=False,
        actual_control_codec_tested=False, original_monotonic_clock=True,
        filesystem_model=True, binding_model=True, source_owner_model=True,
        directory_FD_tested=False, factory_published=False, loader_graph_loaded=False,
        parent_started=False, native_tested=False, device_accessed=False, rf_requested=False,
        receive_available=False, production_admission=False, restoration_verified=False,
        phone_tested=False, private_raw_included=False,
        inputs=[dict(path=name, bytes=size, sha256=digest) for name, size, digest in INPUTS],
        stdout_sha256=ARTIFACTS[1][2], stderr_sha256=ARTIFACTS[2][2])
    report = json.loads(raw['result.json'].decode('ascii'))
    if (type(report) is not dict or set(report) != set(expected) or report != expected or
            any(type(report[key]) is not type(value) for key, value in expected.items())):
        raise ValueError('original_report_scope')
    if raw['stdout.raw'] != WINDOWS_MARKER or re.fullmatch(
            br'\.\r\n-{70}\r\nRan 1 test in 0\.032s\r\n\r\nOK\r\n', raw['stderr.raw']) is None:
        raise ValueError('original_raw_contract')
    private = original / 'private-inputs'
    if sorted(str(path.relative_to(private)).replace('\\', '/') for path in private.rglob('*') if path.is_file()) != \
            sorted(name for name, _, _ in INPUTS):
        raise ValueError('original_snapshot_inventory')
    current_equal = 0
    for name, size, digest in INPUTS:
        saved = _read(private / name, size, digest, retained)
        current_path = BASE / name
        if name != CHECKER:
            current = _read(current_path, size, digest, retained)
            if current != saved:
                raise ValueError('current_source_changed')
            current_equal += 1
        else:
            current = _read(current_path, *FUTURE_CHECKER_PIN, retained)
            if saved.count(OLD_LINE) != 1 or current != saved.replace(OLD_LINE, NEW_LINE, 1):
                raise ValueError('unexpected_future_harness_delta')
    with zipfile.ZipFile(original / 'public-result.zip') as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                any(bundle.read(name) != raw[name] for name in bundle.namelist())):
            raise ValueError('original_zip_readback')
        members = [dict(name=entry.filename, bytes=entry.file_size, crc32=entry.CRC,
            sha256=_sha(bundle.read(entry.filename))) for entry in bundle.infolist()]
    if any(path.read_bytes() != value for path, value in retained.items()):
        raise ValueError('original_changed_during_review')
    return current_equal, members


def main():
    if len(sys.argv) != 1:
        return 2
    equal_count, original_members = _verify()
    report = dict(schema='receive-directory-auth-clock-offline-review-v1', artifact_review_passed=True,
        observed_child_component_passed=True, original_checker_passed=False,
        original_checker_fail_retained=True, original_result=ORIGINAL,
        original_child_invocations=1, original_new_methods=1, original_old_methods=0,
        observed_completed_domains=4, review_child_invocations=0, review_runtime_invocations=0,
        review_test_methods_executed=0, target_AST_reexecuted=False,
        original_target_AST_claim_count=1, original_snapshots_verified=7,
        current_equal_original_source_count=equal_count, future_harness_changed_source_count=1,
        future_harness_revision_executed=False,
        future_harness=dict(path=CHECKER, bytes=FUTURE_CHECKER_PIN[0], sha256=FUTURE_CHECKER_PIN[1]),
        exact_windows_marker_verified=True, exact_Ran1_OK_verified=True,
        original_artifacts_preserved=True, original_members=original_members,
        original_artifacts=[dict(name=name, bytes=size, sha256=digest) for name, size, digest in ARTIFACTS],
        original_inputs=[dict(path=name, bytes=size, sha256=digest) for name, size, digest in INPUTS],
        actual_F_authentication_component=True, actual_control_codec_component=True,
        filesystem_model=True, binding_model=True, source_owner_model=True,
        directory_FD_tested=False, factory_published=False, loader_graph_loaded=False,
        parent_started=False, native_tested=False, device_accessed=False, rf_requested=False,
        receive_available=False, production_admission=False, restoration_verified=False,
        phone_tested=False, private_raw_included=False)
    out = BASE / 'results' / ('receive-directory-auth-clock-offline-review-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir()
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'Offline fixed-artifact review only; zero new runtime/test/AST/child/device invocations. '
        b'The original child completed its one new four-case authentication method with exact Windows CRLF '
        b'marker and Ran1/OK. The original checker FAIL and its raw/snapshots/ZIP remain unchanged. '
        b'The later exact LF/CRLF harness correction is SOURCE only and unexecuted here. '
        b'FS/Binding/source-owner models do not prove physical directory FDs, full deployment, Factory, Parent, '
        b'Native, RF, phone, production admission or restoration. No private raw or inputs in this ZIP.\n')
    members = {'result.json': result, 'README.txt': note}
    for name, value in members.items():
        (out / name).write_bytes(value)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, value in members.items():
            bundle.writestr(name, value)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(name) != value for name, value in members.items()):
            raise ValueError('review_zip_readback')
    print(json.dumps(dict(artifact_review_passed=True, observed_child_component_passed=True,
        original_checker_fail_retained=True, runtime_invocations=0, result_dir=str(out),
        result_zip=str(archive), zip_sha256=_sha(archive.read_bytes()))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
