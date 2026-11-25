"""One affected Owner dispatch HOST contract; default SOURCE, no device action.

The actual old/new _context bodies use explicit host object and dispatch seams.
This verifies semantics, not real permissions, IO, startup or measured speed.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_owner_dispatch_v1_host_check.py'
CMD = 'HOST_MTA_RECEIVE_OWNER_DISPATCH_V1_CONTRACT.cmd'
TEST = 'tests/test_receive_owner_dispatch_v1.py'
SELECTOR = 'ReceiveOwnerDispatchV1Test.test_context_original_and_dispatch_equivalence'
PINS = (
    ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_service_owner.py', 107026,
     'a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7'),
    ('candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py', 107104,
     '22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf'),
    ('candidate/receive-owner-dispatch-v1/generate.py', 9170,
     '0a1219c79bcf53283873a2c79128e0da6ec4d8330f50852adc126dfd46405b40'),
    ('candidate/receive-owner-dispatch-v1/exactsource-delta.json', 2189,
     '49d87f845578545103ab516c46a25e39a62dc3c0bd9003c205b42254ac7203dc'),
    (TEST, 16811, 'a9998af0513c05753065391f2db3e66cf34eb557265f3f2e7c95854957ebe487'),
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'))
README = (b'One actual Owner _context method contract, old/new ASTs compiled unchanged.\n'
          b'Explicit host-only objects record dispatch; real Owner constructors are not called.\n'
          b'70 cases: 3 accepted, 61 guard rejections, 6 original non-guard exceptions.\n'
          b'Each body runs once per case; order, short circuit and failure behavior are compared.\n'
          b'No previous test suite, runtime graph, device, RF or phone operation is executed.\n'
          b'No real IO/permissions, startup completion, physical close or speed claim is made.\n'
          b'Raw child streams, receipt and source snapshots remain private.\n')
CHILD = """import importlib.util,os,sys,unittest
os.environ['P011_OWNER_DISPATCH_SNAPSHOT_ROOT']=sys.argv[2]
os.environ['P011_OWNER_DISPATCH_RECEIPT']=sys.argv[3]
spec=importlib.util.spec_from_file_location('fixed_owner_dispatch_fixture',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[4],module)
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
"""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(name):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2097152:
        raise ValueError('fixed_file')
    metadata = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink,
                          v.st_size, v.st_mtime_ns, v.st_ctime_ns)
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                 opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not equal:
            raise ValueError('fixed_identity')
        raw = handle.read(2097153)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]:
        raise ValueError('fixed_changed')
    return raw


def declarations(raw, name, path, strip_guard=False):
    tree = ast.parse(raw, feature_version=(3, 5))
    guards = [n for n in tree.body if isinstance(n, ast.If)]
    if strip_guard:
        if len(guards) != 1 or ast.dump(guards[0].test) != ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body):
            raise ValueError('fixed_main_guard')
        tree.body.remove(guards[0])
    elif guards:
        raise ValueError('unexpected_source_guard')
    module = types.ModuleType(name)
    module.__file__ = str(BASE / path)
    exec(compile(tree, module.__file__, 'exec'), module.__dict__)
    return module


def source_contract(inputs):
    generator = declarations(inputs[PINS[2][0]], 'fixed_owner_dispatch_plan', PINS[2][0], True)
    outputs, facts = generator.prepare(inputs[PINS[0][0]])
    if (tuple(row['path'] for row in outputs) != (PINS[1][0], PINS[3][0]) or
            tuple(row['raw'] for row in outputs) != (inputs[PINS[1][0]], inputs[PINS[3][0]]) or
            facts['byte_delta'] != 78 or facts['business_delta_count'] != 1):
        raise ValueError('complete_owner_dispatch_inverse')
    fixture = ast.parse(inputs[TEST], feature_version=(3, 5))
    methods = [n.name for c in fixture.body if isinstance(c, ast.ClassDef)
               for n in c.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    if methods != [SELECTOR.split('.')[1]]:
        raise ValueError('one_affected_method')
    return dict(byte_delta=78, complete_byte_ast_inverse_verified=True,
                unchanged_other_definitions_verified=True, one_affected_method_verified=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    mode = 'host' if args.run_host else 'source'
    out = BASE / 'results' / ('receive-owner-dispatch-v1-' + mode + '-' +
          datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, sealer, evidence = {}, None, None
    report = dict(schema='p011-owner-dispatch-v1-affected-contract', mode=mode, passed=False,
        error=None, source_checked=False, source_preserved=False, child_invoked=False,
        host_exit='NOT_RUN', methods_requested=1, cases_requested=70, methods_verified=None,
        cases_verified=None, actual_context_calls=None, selector=SELECTOR, old_methods_run=0,
        explicit_host_dispatch_models=True, runtime_graph_executed=False, device=False,
        rf=False, phone=False, real_io_permissions_verified=False, measured_performance_claim=False)

    def read(path, pin=None):
        raw = read_fixed(path)
        if evidence is not None:
            evidence._retain(path, raw)
        else:
            inputs[path] = raw
        if pin is not None and (len(raw), sha(raw)) != pin:
            raise ValueError('fixed_input_pin')
        return raw

    try:
        if sys.platform != 'win32':
            raise ValueError('fixed_windows_host')
        seal = PINS[-1]
        raw = read(seal[0], seal[1:])
        sealer = declarations(raw, 'fixed_owner_dispatch_sealer', seal[0])
        evidence = sealer.InputEvidence(inputs)
        for path, size, digest in PINS[:-1]:
            read(path, (size, digest))
        read(SELF); read(CMD)
        report.update(source_contract(inputs), source_checked=True)
        evidence.snapshot(out, lambda name: name)
        if args.run_host:
            report['child_invoked'] = True
            receipt_path = private / 'host-receipt.private.json'
            child = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD,
                str(out / 'private-inputs' / TEST), str(out / 'private-inputs'),
                str(receipt_path), SELECTOR], cwd=str(out), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30)
            sealer.fresh(private / 'stdout.raw', child.stdout)
            sealer.fresh(private / 'stderr.raw', child.stderr)
            report.update(host_exit=child.returncode, stdout_bytes=len(child.stdout),
                stdout_sha256=sha(child.stdout), stderr_bytes=len(child.stderr), stderr_sha256=sha(child.stderr))
            if child.returncode != 0 or not receipt_path.is_file():
                raise ValueError('affected_method_failed')
            raw = receipt_path.read_bytes()
            if not 0 < len(raw) <= 8192:
                raise ValueError('finite_receipt')
            receipt = json.loads(raw.decode('ascii'))
            expected = dict(schema='p011-receive-owner-dispatch-v1-host-receipt',
                selector='tests.test_receive_owner_dispatch_v1.' + SELECTOR, passed=True,
                source_pins=[list(p) for p in PINS[:4]], source_inputs_preserved=True,
                methods=1, cases=70, actual_context_calls=140, accepted_cases=3,
                guard_rejection_cases=61, original_non_guard_exception_cases=6,
                nine_method_fields_per_index=4, original_check_order_verified=True,
                original_failure_short_circuit_verified=True, byte_delta=78,
                fixed_source_byte_ast_inverse_verified=True, device_executed=False,
                rf_executed=False, surrounding_runtime_executed=False,
                real_io_permissions_verified=False, measured_performance_claim=False)
            if receipt != expected:
                raise ValueError('exact_affected_receipt')
            report.update(methods_verified=1, cases_verified=70, actual_context_calls=140)
    except BaseException as failure:
        report['error'] = type(failure).__name__
        if sealer is not None:
            sealer.fresh(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if evidence is not None:
            try:
                evidence.snapshot(out, lambda name: name)
                report['source_preserved'] = (bool(inputs) and not evidence.partial and all(
                    read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in inputs.items()))
            except BaseException as failure:
                report['error'] = report['error'] or type(failure).__name__
                report['source_preserved'] = False
    report['source_count'] = len(inputs)
    report['passed'] = (report['error'] is None and report['source_checked'] and report['source_preserved'] and
        (not args.run_host or report['methods_verified'] == 1 and report['cases_verified'] == 70))
    report['checker_exit'] = 0 if report['passed'] else 1
    report['input_pins'] = [dict(path=p, bytes=len(raw), sha256=sha(raw)) for p, raw in inputs.items()]
    if sealer is None:
        print(json.dumps(dict(passed=False, mode=mode, result_dir=str(out), error=report['error'])))
        return 1
    sealed = sealer.seal_result(out, report, README)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode, result_dir=str(out),
        public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
