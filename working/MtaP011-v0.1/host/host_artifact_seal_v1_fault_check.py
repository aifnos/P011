"""Run the one new HOST IO fault method and retain its exact inputs and streams.

No SOURCE/build/binding main, old suite, device, RF or user transfer is run.
"""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import traceback
import uuid

BASE = Path(__file__).resolve().parents[1]
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/receive_durable_gui_v1_pc_check.py', 11583,
     '6e77ef506e409ffc057e53dc6bbe8c242e24180a934755cbaf73855f4da9ae4b'),
    ('host/receive_durable_gui_v1_binding_check.py', 6880,
     'a657e5a2ceedfeec7bcba254f62a760537bfec8c68709369bc97c13fc2287867'),
    ('host/receive_durable_state_v1_source_check.py', 8764,
     '71b92ea5c03b43dba81948b58c273e84961ec2c25f1a5e4403340cc0f47a615b'),
    ('tests/test_host_artifact_seal_v1.py', 10064,
     '10c3d1ea8d6c3d1fe64c8c2d04053c5754057649372510b12b61b3eb159dee3f'),
)
METHOD = 'HostArtifactSealV1Tests.test_partial_inputs_and_private_zip_fault_contract'


def main():
    if sys.argv[1:] or sys.platform != 'win32' or BASE != Path(r'D:\project\P011\working\MtaP011-v0.1'):
        raise ValueError('fixed_development_pc_only')
    out = BASE / 'results' / ('host-artifact-seal-v1-fault-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    helper_path = BASE / PINS[0][0]
    spec = importlib.util.spec_from_file_location('fixed_host_fault_evidence', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    inputs = {}
    evidence = helper.InputEvidence(inputs)
    stdout, stderr, error = b'', b'', None
    child_exit, timeout, unchanged = None, False, False
    try:
        for path, size, sha in PINS:
            evidence.read(BASE / path, key=path, pin=(size, sha))
        evidence.read(Path(__file__), key='host/host_artifact_seal_v1_fault_check.py')
        evidence.read(BASE / 'HOST_MTA_ARTIFACT_SEAL_V1_FAULT_CHECK.cmd',
                      key='HOST_MTA_ARTIFACT_SEAL_V1_FAULT_CHECK.cmd')
        evidence.snapshot(out, lambda name: name)
        child = subprocess.run([sys.executable, '-I', '-B', str(BASE / PINS[-1][0]), METHOD],
            cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30)
        child_exit, stdout, stderr = child.returncode, child.stdout, child.stderr
        if child_exit != 0 or stdout.strip() != b'HOST_ARTIFACT_SEAL_V1_FAULT_CONTRACT=1':
            raise ValueError('unique_fault_method_failed')
        unchanged = all((BASE / name).read_bytes() == raw for name, raw in inputs.items())
        if not unchanged:
            raise ValueError('source_changed')
    except subprocess.TimeoutExpired as failure:
        timeout, stdout, stderr = True, failure.stdout or b'', failure.stderr or b''
        error = 'unique_fault_method_timeout'
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        exception = traceback.format_exc().encode('utf-8')
    try:
        evidence.snapshot(out, lambda name: name)
        helper.fresh(out / 'private-raw/stdout.raw', stdout)
        helper.fresh(out / 'private-raw/stderr.raw', stderr)
        if 'exception' in locals():
            helper.fresh(out / 'private-raw/checker-exception.txt', exception)
    except BaseException as failure:
        error = (error + ';' if error else '') + 'evidence_failed:' + type(failure).__name__ + ':' + str(failure)
    passed = error is None and child_exit == 0 and unchanged and not timeout
    report = dict(schema='p011-host-artifact-seal-v1-fault-check', passed=passed,
        host_exit=0 if passed else 1, child_exit=child_exit, timeout=timeout, error=error,
        remote_exit='NOT_RUN_PC_ONLY', source_preserved=unchanged,
        method=METHOD, child_invocations=1 if child_exit is not None or timeout else 0,
        evidence_level='HOST_IO_HELPER_AND_READER_FAULT_FIXTURES_ONLY',
        old_tests_replayed=0, source_build_binding_main_executed=False,
        device=False, rf=False, phone=False, deployed=False, restoration_verified=False,
        inputs=[dict(path=name, bytes=len(raw), sha256=helper.digest(raw),
                     complete=name not in evidence.partial) for name, raw in inputs.items()])
    sealed = helper.seal_result(out, report,
        b'One new HOST IO helper/actual reader fault method only.\n'
        b'Partial/rejected inputs and ZIP write/readback/publication ordering use narrow fixtures.\n'
        b'No old tests, SOURCE/build/binding main, P011, RF, phone, deployment or restoration.\n'
        b'Exact inputs and stdout/stderr remain private.\n')
    final = sealed['report']
    print(json.dumps(dict(passed=final['passed'], child_exit=child_exit, error=final['error'],
        result=str(out / 'result.json'), zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
