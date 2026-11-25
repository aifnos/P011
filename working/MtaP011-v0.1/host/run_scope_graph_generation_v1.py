"""Capture one new PC graph plan/write attempt; no device or old workflow.

The fixed generator performs its own complete input/output checks. This runner
retains separate raw child streams and timeout evidence before sealing a report.
"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import traceback

BASE = Path(__file__).resolve().parents[1]
GEN = ('candidate/receive-scope-dispatch-graph-v1/generate_graph.py', 24987,
       'ad8932e0de8648e3e459a1c9442e29dc5f6a25dd62b91422ec93ac1ea19a955a')
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')


def main():
    if sys.argv[1:] not in ([], ['--write']):
        raise ValueError('fixed_plan_or_write')
    mode = 'write' if sys.argv[1:] else 'plan'
    out = BASE / 'results' / ('receive-scope-dispatch-graph-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs = {}
    for path, size, digest in (GEN, SEAL):
        raw = (BASE / path).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, digest):
            raise ValueError('fixed_input_pin')
        inputs[path] = raw
    own = str(Path(__file__).resolve().relative_to(BASE)).replace('\\', '/')
    inputs[own] = Path(__file__).read_bytes()
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location('scope_graph_sealer', BASE / SEAL[0]))
    exec(compile(inputs[SEAL[0]], str(BASE / SEAL[0]), 'exec'), module.__dict__)
    evidence = module.InputEvidence(inputs)
    evidence.snapshot(out, lambda name: name)
    report = dict(passed=False, mode=mode, error=None, host_exit=None,
        source_preserved=False, generator_child_invoked=False, device_invoked=False,
        rf_invoked=False, runtime_graph_executed=False, phone_verified=False)
    try:
        report['generator_child_invoked'] = True
        child = subprocess.run([sys.executable, '-I', '-B', str(BASE / GEN[0])] + sys.argv[1:],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        rawout, rawerr = child.stdout, child.stderr
        report['host_exit'] = child.returncode
    except subprocess.TimeoutExpired as failure:
        rawout, rawerr = failure.stdout or b'', failure.stderr or b''
        report.update(host_exit='TIMEOUT', error='TimeoutExpired')
    except BaseException as failure:
        rawout, rawerr = b'', b''
        module.fresh(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
        report['error'] = type(failure).__name__
    module.fresh(private / 'stdout.raw', rawout)
    module.fresh(private / 'stderr.raw', rawerr)
    module.fresh(private / 'host-exit', (str(report['host_exit']) + '\n').encode('ascii'))
    report.update(stdout_bytes=len(rawout), stderr_bytes=len(rawerr),
        stdout_sha256=hashlib.sha256(rawout).hexdigest(), stderr_sha256=hashlib.sha256(rawerr).hexdigest())
    report['source_preserved'] = all((BASE / path).read_bytes() == raw for path, raw in inputs.items())
    report['passed'] = report['error'] is None and report['host_exit'] == 0 and not rawerr and report['source_preserved']
    sealed = module.seal_result(out, report,
        b'One fixed new PC graph generator child. Raw stdout/stderr/exit retained privately.\n'
        b'PASS means generator process completed with its own checks and source preserved.\n'
        b'Not actual startup, RF, phone transfer or network restoration acceptance.\n')
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        result_dir=str(out), archive_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
