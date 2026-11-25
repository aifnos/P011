"""Offline review of one immutable HOST run; never launch a runtime or test.

The original checker remains FAIL. This tool verifies its original artifacts
and records the observed child component PASS after removing exactly one pinned
WSL environment-warning line in a derived stderr view. Raw files stay private
and unchanged. The two subsequent harness edits have not been executed.
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
ORIGINAL = 'results/receive-bound-integration-host-20261004-034535-689b30bd'
ARTIFACTS = (
    ('result.json', 3366, '823693ef075d520a04c793163be27fabc6adb83ea4a21ea70e93006a9d86f130'),
    ('stdout.raw', 706, 'ce428d4a4c2330c00730f230af7fe63dd8f92d7a1321c3757b2d6faacbd5f8d9'),
    ('stderr.raw', 188, 'a3f0fb45af313a27435d1597fff46a59661f0e61a1cf45040f6a37d49ac4b2b4'),
    ('README.txt', 434, 'd0fcb6a2a09e3dd855e6a1e2970ecde5e5493578e460561a63d33f8b4cdf863c'),
    ('public-result.zip', 1864, 'f9b101e0656e0cc3c4c992aa66b7d6ce0f1119b302f3a457ae5f92c02dac0681'),
)
INPUTS = (
    ('tests/test_receive_bound_integration.py', 13746, '2c4b064658152f60a6f593521db69db0bfd81e91096c9ed27ec3d36bcaee1136'),
    ('host/receive_bound_integration_check.py', 5802, 'f772ae19bbc6e885e71c7fb1e110c00ea44e594f75ba99917cbe68f29104c5ed'),
    ('HOST_MTA_RECEIVE_BOUND_INTEGRATION_CHECK.cmd', 97, '8dafe30a035976492f11bafc66c0f5dd00c9c8f8e7ea52734c5627bce2edcd78'),
    ('tests/test_sender_pump.py', 34154, '7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7'),
    ('runtime/mta_send_preparation.py', 28532, '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('runtime/mta_sender_pump.py', 33455, '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c'),
    ('runtime/mta_protocol.py', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('candidate/file-utf8-v67/runtime/mta_files.py', 10987, 'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('candidate/receive-directory-fd-v1/runtime/mta_storage.py', 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('candidate/receive-directory-fd-v1/runtime/mta_transport.py', 40047, 'c5c305bc2fb974392940f483d9cad1f8866230f24e490fefe25401b43ead82ba'),
)
UNEXECUTED_HARNESS = {
    'tests/test_receive_bound_integration.py': (13877, 'd0790f870bf62848ccfcb6f8c4937dbd6961aae63c5d849179f84af2187798ee'),
    'host/receive_bound_integration_check.py': (6177, '30f20d9a8b520d6262df83b7eb7aef2ca639330011c829c1fc870de144863b84'),
}
WARNING = (b"wsl: Failed to start the systemd user session for 'admin'. "
           b'See journalctl for more details.\n')
TRUE_FIELDS = (
    'actual_linux_directory_fd', 'actual_prepared_send', 'actual_receiver_transport',
    'actual_sender_pump', 'binding_closure_verified', 'chinese_file_commit_verified',
    'consent_blocked_download_verified', 'filecenter_read_verified',
    'host_loopback_admission_fixture', 'host_loopback_owner', 'local_commit_verified',
    'one_original_archive_handle', 'original_binding_borrowed', 'passed',
    'peer_ack_verified', 'socket_file_cleanup_verified',
)
FALSE_FIELDS = ('device_tested', 'full_restore_verified', 'phone_tested', 'rf_requested')
COUNTS = dict(actual_tls_connections=2, new_methods=1, old_methods=0)
REPORT_KEYS = frozenset((
    'actual_p011', 'child_exit', 'child_invocations', 'inputs', 'integration',
    'new_methods', 'old_methods', 'passed', 'phone', 'production_admission',
    'source_snapshots_equal', 'stderr_sha256', 'stdout_sha256',
    'target_python35_ast_sources', 'timeout',
))


def _require(value, code):
    if not value:
        raise ValueError(code)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, count, digest):
    raw = path.read_bytes()
    _require(len(raw) == count and _hash(raw) == digest, 'original_bytes_changed')
    return raw


def _component(value):
    _require(type(value) is dict and set(value) == set(TRUE_FIELDS + FALSE_FIELDS) | set(COUNTS),
             'component_shape')
    _require(all(value[name] is True for name in TRUE_FIELDS) and
             all(value[name] is False for name in FALSE_FIELDS), 'component_boundaries')
    _require(all(type(value[name]) is int and value[name] == count
                 for name, count in COUNTS.items()), 'component_counts')
    return value


def _write_new(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)
    _require(path.read_bytes() == raw, 'review_readback')


def main():
    if len(sys.argv) != 1:
        return 2
    old = BASE / ORIGINAL
    raw = {name: _read(old / name, count, digest) for name, count, digest in ARTIFACTS}
    report = json.loads(raw['result.json'].decode('ascii'))
    _require(type(report) is dict and set(report) == REPORT_KEYS, 'report_shape')
    _require(report['passed'] is False and report['actual_p011'] is False and
             report['phone'] is False and report['production_admission'] is False and
             report['timeout'] is False and report['source_snapshots_equal'] is True,
             'original_checker_boundaries')
    for name, count in (('child_exit', 0), ('child_invocations', 1), ('new_methods', 1),
                        ('old_methods', 0), ('target_python35_ast_sources', 1)):
        _require(type(report[name]) is int and report[name] == count, 'original_checker_counts')
    _require(report['stdout_sha256'] == _hash(raw['stdout.raw']) and
             report['stderr_sha256'] == _hash(raw['stderr.raw']), 'raw_report_binding')
    _require(raw['stdout.raw'].startswith(b'RESULT=') and raw['stdout.raw'].endswith(b'\n') and
             raw['stdout.raw'].count(b'\n') == 1, 'stdout_one_result')
    component = _component(json.loads(raw['stdout.raw'][7:-1].decode('ascii')))
    _require(_component(report['integration']) == component, 'component_report_binding')
    expected_stdout = b'RESULT=' + json.dumps(component, sort_keys=True).encode('ascii') + b'\n'
    _require(raw['stdout.raw'] == expected_stdout, 'stdout_canonical')
    _require(raw['stderr.raw'].startswith(WARNING) and raw['stderr.raw'].count(WARNING) == 1,
             'single_exact_wsl_warning')
    derived = raw['stderr.raw'][len(WARNING):]
    _require(re.fullmatch(br'-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived) is not None,
             'strict_unittest_summary')

    expected_inputs = [dict(path=name, bytes=count, sha256=digest) for name, count, digest in INPUTS]
    _require(report['inputs'] == expected_inputs, 'original_input_plan')
    private = old / 'private-inputs'
    _require({path.relative_to(private).as_posix() for path in private.rglob('*') if path.is_file()}
             == {name for name, count, digest in INPUTS}, 'snapshot_file_set')
    saved, current = {}, {}
    for name, count, digest in INPUTS:
        saved[name] = _read(private / name, count, digest)
        current_count, current_digest = UNEXECUTED_HARNESS.get(name, (count, digest))
        current[name] = _read(BASE / name, current_count, current_digest)
        if name not in UNEXECUTED_HARNESS:
            _require(current[name] == saved[name], 'retained_current_input')
        else:
            _require(current[name] != saved[name], 'harness_revision_not_separate')
    old_members = {'result.json': raw['result.json'], 'README.txt': raw['README.txt']}
    with zipfile.ZipFile(old / 'public-result.zip', 'r') as bundle:
        _require(bundle.namelist() == list(old_members) and bundle.testzip() is None, 'original_zip_crc')
        _require(all(bundle.read(name) == value for name, value in old_members.items()),
                 'original_zip_readback')
    # Pre/post checks use original bytes, not normalized summaries. No old
    # artifact or current runtime/harness is edited by this offline tool.
    _require(all((old / name).read_bytes() == value for name, value in raw.items()) and
             all((private / name).read_bytes() == value for name, value in saved.items()) and
             all((BASE / name).read_bytes() == value for name, value in current.items()),
             'review_input_changed')

    result = dict(
        review_passed=True, observed_child_component_passed=True,
        original_checker_passed=False, original_checker_fail_retained=True,
        runtime_invocations=0, repeated_test_methods=0, test_methods_executed_by_review=0,
        ast_invocations=0, adb_invocations=0, wsl_invocations=0,
        device_accessed=False, actual_p011=False, phone=False, rf_requested=False,
        production_admission=False, full_restore_verified=False, state_f_integration=False,
        exact_environment_warning_lines_removed_from_derived_view=1,
        original_child_exit=0, original_child_invocations=1, original_new_methods=1,
        original_old_methods=0, original_timeout=False,
        original_target_python35_ast_sources_reported=1, ast_declaration_not_reexecuted=True,
        original_result=ORIGINAL, original_artifacts_verified=[
            dict(name=name, bytes=count, sha256=digest) for name, count, digest in ARTIFACTS],
        original_snapshots_verified=12, retained_current_inputs_verified=10,
        post_test_harness_revisions_not_executed=True,
        unexecuted_harness_revisions=[dict(path=name, bytes=count, sha256=digest)
                                     for name, (count, digest) in UNEXECUTED_HARNESS.items()],
        integration=component)
    result_raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        b'Offline artifact review only; no test, runtime, AST, WSL or ADB invocation. '
        b'The original checker FAIL and all raw/snapshots/ZIP bytes remain unchanged. '
        b'The original child exited 0 and one new HOST Linux bound TLS receive component '
        b'method reported PASS with strict Ran 1 / OK after exactly one pinned WSL '
        b'environment-warning line was removed only in a derived view. '
        b'Original 12 snapshots verified; 10 unchanged current inputs verified; two '
        b'later failure-only harness revisions were not executed by this review. '
        b'Actual HOST directory FD/archive/commit/FileCenter/ACK evidence only; '
        b'loopback owner and admission remain fixtures. Not State/F, P011, phone, RF, '
        b'production admission or physical restore. Raw, private inputs and keys excluded.\n')
    out = BASE / 'results' / ('receive-bound-result-review-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir()
    members = {'result.json': result_raw, 'README.txt': readme}
    for name, value in members.items():
        _write_new(out / name, value)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, value in members.items():
            bundle.writestr(name, value)
    with zipfile.ZipFile(archive, 'r') as bundle:
        _require(bundle.namelist() == list(members) and bundle.testzip() is None, 'review_zip_crc')
        _require(all(bundle.read(name) == value for name, value in members.items()), 'review_zip_readback')
    print(json.dumps(dict(review_passed=True, observed_child_component_passed=True,
                         original_checker_passed=False, runtime_invocations=0,
                         result_dir=str(out), zip_bytes=archive.stat().st_size,
                         zip_sha256=_hash(archive.read_bytes())), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
