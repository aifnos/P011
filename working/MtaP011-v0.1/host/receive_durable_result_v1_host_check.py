"""One affected HOST WSL method; no device, RF, graph deployment or phone."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_durable_result_v1.py'
SELECTOR = 'ReceiveDurableResultV1Tests.test_current_publication_failure_retention'
SELF = 'host/receive_durable_result_v1_host_check.py'
MANIFEST = 'host/formal_receive_profile_classification_clock_v1_definition_manifest.json'
PINNED = (
    ('tests/test_receive_directory_fd.py', 21074, '218966bbcae1a539e61ec3088f2cdcb96bdc0312cac7b1ce352033e188a9327b'),
    ('candidate/receive-directory-fd-v1/runtime/mta_storage.py', 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('candidate/receive-directory-clock-v2/runtime/mta_transport.py', 40223, '171efb7cdfabbe4ea826afc03df6b401d1ee2b55cf23810e1fc7fb7b11f89826'),
    ('candidate/receive-durable-result-v1/runtime/mta_storage.py', 56595, '365490e2dfe8a2c65d2b38fc8ae1a49747d09ed3b127677e9fe61e69866052d0'),
    ('candidate/receive-durable-result-v1/runtime/mta_transport.py', 41435, '9b05ef49059e9b06536de32186e7de1cfd531461d3e096eb266d49f760069f8e'),
    ('runtime/mta_protocol.py', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'))
SOURCES = tuple(row[0] for row in PINNED) + (TEST, SELF, MANIFEST,
    'candidate/receive-durable-result-v1/exactsource-delta.json',
    'HOST_MTA_RECEIVE_DURABLE_RESULT_V1_CHECK.cmd')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('host_result_write')
    if path.read_bytes() != raw:
        raise ValueError('host_result_readback')


def main():
    if len(sys.argv) != 1:
        return 2
    originals = {path: (BASE / path).read_bytes() for path in SOURCES}
    if any((len(originals[path]), sha(originals[path])) != (count, pin)
           for path, count, pin in PINNED):
        raise ValueError('frozen_input_changed')
    selected = json.loads(originals[MANIFEST])['sources']
    for module, path in (('mta_storage', PINNED[1][0]), ('mta_transport', PINNED[2][0])):
        rows = [row for row in selected if row['module'] == module]
        if len(rows) != 1 or rows[0]['path'] != path or \
                rows[0]['sha256'] != sha(originals[path]) or rows[0]['bytes'] != len(originals[path]):
            raise ValueError('actual_selected_original_differs')
    for path in (PINNED[3][0], PINNED[4][0]):
        ast.parse(originals[path].decode('utf-8'), feature_version=(3, 5))
    out = BASE / 'results' / ('receive-durable-result-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-inputs'
    for path, raw in originals.items():
        fresh(private / path, raw)
    target = str(private / TEST)
    if not target.startswith('D:\\project\\P011\\working\\MtaP011-v0.1\\results\\'):
        raise ValueError('fixed_workspace_required')
    target = '/mnt/d/' + target[3:].replace('\\', '/')
    timed_out = False
    try:
        child = subprocess.run(['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
            '-I', '-B', target, SELECTOR], cwd=str(private), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=45)
        code, stdout, stderr = child.returncode, child.stdout, child.stderr
    except subprocess.TimeoutExpired as failure:
        code, stdout, stderr = None, failure.stdout or b'', failure.stderr or b''
        timed_out = True
    fresh(out / 'private-raw/stdout.raw', stdout)
    fresh(out / 'private-raw/stderr.raw', stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
        (private / path).read_bytes() == raw for path, raw in originals.items())
    projection = None
    if stdout.startswith(b'RESULT=') and stdout.count(b'\n') == 1:
        try:
            projection = json.loads(stdout[7:])
        except (ValueError, UnicodeError):
            pass
    passed = (code == 0 and not timed_out and unchanged and
        b'Ran 1 test' in stderr and stderr.rstrip().endswith(b'OK') and
        type(projection) is dict and projection.get('passed') is True and
        projection.get('methods') == 1 and projection.get('domains') == 11 and
        projection.get('old_methods') == 0 and projection.get('device') is False and
        projection.get('phone') is False and projection.get('network') is False)
    report = dict(kind='receive_durable_result_v1_HOST', passed=passed,
        child_exit=code, host_exit=0 if passed else 1, timeout=timed_out,
        child_invocations=1, methods_requested=1, old_methods_run=0,
        actual_selected_graph_changed=False, candidate_connected_to_ipc_ui=False,
        device=False, phone=False, rf=False, actual_tls=False, native_owner=False,
        full_restore_verified=False, source_snapshots_equal=unchanged,
        target_python35_ast_sources=2, observation=projection,
        inputs=[dict(path=path, bytes=len(raw), sha256=sha(raw)) for path, raw in originals.items()],
        streams=[dict(name=name, bytes=len(raw), sha256=sha(raw))
            for name, raw in (('stdout.raw', stdout), ('stderr.raw', stderr))])
    members = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (
            b'One new HOST WSL Linux method, eleven affected domains. Original late cancellation defect '
            b'is reproduced; isolated Storage/Transport candidates retain historical durable bytes while '
            b'preserving the original exception and never synthesizing a peer ACK. ZIP/CRC/fsync/FD '
            b'storage operations are native in new private test trees. WSS/connect/check/download/consent '
            b'and socket lifecycle are explicit narrow fixtures, not actual network/TLS/Owner evidence. '
            b'Post-publication close refusal is a fixture, not a native OS close fault. '
            b'Old test definitions are reused without running old methods. Actual selected graph is unchanged; '
            b'Executor/IPC/Bridge/UI still need connection before claiming end-to-end repair. '
            b'No P011, phone, RF, deployment or full restore result. Raw streams and source snapshots private.\n')}
    for path, raw in members.items():
        fresh(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in members.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(path) != raw for path, raw in members.items()):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, child_exit=code, host_exit=0 if passed else 1,
        timeout=timed_out, result=str(out / 'result.json'), zip=str(archive),
        zip_sha256=sha(archive.read_bytes())), sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
