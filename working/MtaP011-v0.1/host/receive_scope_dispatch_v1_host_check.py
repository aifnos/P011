"""One changed Scope _originals HOST contract; default SOURCE, no device.

Actual full method ASTs are compiled; explicit models stop at the unchanged
continuation seam. This verifies changed dispatch, not full runtime/IO or speed.
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
SELF = 'host/receive_scope_dispatch_v1_host_check.py'
CMD = 'HOST_MTA_RECEIVE_SCOPE_DISPATCH_V1_CONTRACT.cmd'
TEST = 'tests/test_receive_scope_dispatch_v1.py'
SELECTOR = 'ReceiveScopeDispatchV1Test.test_originals_dispatch_equivalence'
PINS = (
    ('candidate/receive-owner-dispatch-graph-v1/runtime/mta_client_receive_factory.py', 99257,
     '0103f047e9598767f9e9162cf8833f0420c171f7552c31ed28e107e6a91c6cb0'),
    ('candidate/receive-scope-dispatch-v1/runtime/mta_client_receive_factory.py', 99371,
     '7c4ee1b5dabf869301be940e0330968b683bde2e8d7d45add83f63c474c70f15'),
    ('candidate/receive-scope-dispatch-v1/generate.py', 11297,
     '52fb3a632d170bbd0b8617203de66069a23de065311da79a4a70fd86b35ec2ab'),
    ('candidate/receive-scope-dispatch-v1/exactsource-delta.json', 3469,
     'be87cdbd4830f79164787277d4c189b577fb7854d6ee125bd2d4e14434a4d768'),
    (TEST, 23077, 'cda2a13d5750e94fd9774f23eb357e3a7959d7bb96539d95bf28e59d82f72dde'),
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'))
README = (b'One changed Scope _originals method contract; default SOURCE, explicit --run-host.\n'
    b'Original/new full method ASTs compiled unchanged; field-model execution stops at a seam.\n'
    b'Compare changed guards, eager tuple reads, short circuit, original errors and continuation.\n'
    b'No real Scope/Owner constructor, later IO/Directory checks, runtime graph, device or RF call.\n'
    b'Unchanged remainder is source/inverse evidence, not actual execution or permission proof.\n'
    b'No old suite, benchmark or original main is called; measured speed is not certified.\n'
    b'Private snapshots, raw child streams and exact receipt retained; ZIP only result and README.\n')
CHILD = """import importlib.util,os,sys,unittest
os.environ['P011_SCOPE_DISPATCH_SNAPSHOT_ROOT']=sys.argv[2]
os.environ['P011_SCOPE_DISPATCH_RECEIPT']=sys.argv[3]
spec=importlib.util.spec_from_file_location('fixed_scope_dispatch_fixture',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[4],module)
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
"""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


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
        need(equal, 'fixed_identity')
        raw = handle.read(2097153)
        need(metadata(os.fstat(handle.fileno())) == opened, 'fixed_changed')
    need(metadata(path.lstat()) == before and len(raw) == before[4], 'fixed_changed')
    return raw


def declarations(raw, name, path, strip_guard=False):
    tree = ast.parse(raw, feature_version=(3, 5))
    guards = [node for node in tree.body if isinstance(node, ast.If)]
    if strip_guard:
        need(len(guards) == 1 and ast.dump(guards[0].test) ==
             ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body), 'fixed_main_guard')
        tree.body.remove(guards[0])
    else:
        need(not guards, 'unexpected_source_guard')
    module = types.ModuleType(name)
    module.__file__ = str(BASE / path)
    exec(compile(tree, module.__file__, 'exec'), module.__dict__)
    return module


def literal(raw, name):
    tree = ast.parse(raw, feature_version=(3, 5))
    nodes = [node.value for node in tree.body if isinstance(node, ast.Assign) and
             any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(nodes) == 1, 'single_fixture_literal')
    return ast.literal_eval(nodes[0])


def source_contract(inputs):
    generator = declarations(inputs[PINS[2][0]], 'fixed_scope_dispatch_plan', PINS[2][0], True)
    outputs, facts = generator.prepare(inputs[PINS[0][0]])
    need(tuple(row['path'] for row in outputs) == (PINS[1][0], PINS[3][0]) and
         tuple(row['raw'] for row in outputs) == (inputs[PINS[1][0]], inputs[PINS[3][0]]) and
         facts['business_delta_count'] == 1 and facts['byte_delta'] == 114, 'complete_scope_inverse')
    tree = ast.parse(inputs[TEST], feature_version=(3, 5))
    methods = [node.name for cls in tree.body if isinstance(cls, ast.ClassDef)
               for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    need(methods == [SELECTOR.split('.')[1]], 'one_affected_method')
    expected = literal(inputs[TEST], 'EXPECTED_RECEIPT')
    need(type(expected) is dict and expected.get('source_pins') == PINS[:4] and
         expected.get('methods') == 1 and expected.get('whole_method_execution_verified') is False and
         expected.get('full_method_ast_compiled') is True, 'fixed_receipt_scope')
    return json.loads(json.dumps(expected))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    mode = 'host' if args.run_host else 'source'
    out = BASE / 'results' / ('receive-scope-dispatch-v1-' + mode + '-' +
          datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, sealer, evidence = {}, None, None
    report = dict(schema='p011-scope-dispatch-v1-affected-contract', mode=mode, passed=False,
        error=None, source_checked=False, source_preserved=False, child_invoked=False,
        host_exit='NOT_RUN', methods_requested=1, methods_verified=None, cases_verified=None,
        receipt_verified=False, selector=SELECTOR, byte_delta=114, old_methods_run=0,
        full_method_ast_compiled=False, whole_method_execution_verified=False,
        runtime_graph_executed=False, device=False, rf=False, phone=False,
        real_io_permissions_verified=False, measured_performance_claim=False)

    def read(path, pin=None):
        raw = read_fixed(path)
        if evidence is not None:
            evidence._retain(path, raw)
        else:
            inputs[path] = raw
        if pin is not None:
            need((len(raw), sha(raw)) == pin, 'fixed_input_pin')
        return raw

    try:
        need(sys.platform == 'win32' and all(row[1] > 0 and re.fullmatch(r'[0-9a-f]{64}', row[2])
                                          for row in PINS), 'fixed_frozen_host')
        seal = PINS[-1]
        sealer = declarations(read(seal[0], seal[1:]), 'fixed_scope_dispatch_sealer', seal[0])
        evidence = sealer.InputEvidence(inputs)
        for path, size, digest in PINS[:-1]:
            read(path, (size, digest))
        read(SELF); read(CMD)
        expected = source_contract(inputs)
        report['source_checked'] = True
        evidence.snapshot(out, lambda name: name)
        if args.run_host:
            report['child_invoked'] = True
            receipt_path = private / 'host-receipt.private.json'
            try:
                child = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD,
                    str(out / 'private-inputs' / TEST), str(out / 'private-inputs'),
                    str(receipt_path), SELECTOR], cwd=str(out), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=30)
            except subprocess.TimeoutExpired as failure:
                sealer.fresh(private / 'stdout.raw', failure.stdout or b'')
                sealer.fresh(private / 'stderr.raw', failure.stderr or b'')
                report['host_exit'] = 'TIMEOUT'
                raise
            sealer.fresh(private / 'stdout.raw', child.stdout)
            sealer.fresh(private / 'stderr.raw', child.stderr)
            report.update(host_exit=child.returncode, stdout_bytes=len(child.stdout),
                stdout_sha256=sha(child.stdout), stderr_bytes=len(child.stderr), stderr_sha256=sha(child.stderr))
            need(child.returncode == 0 and receipt_path.is_file(), 'affected_method_failed')
            raw = receipt_path.read_bytes()
            need(0 < len(raw) <= 8192, 'finite_receipt')
            receipt = json.loads(raw.decode('ascii'))
            need(receipt == expected, 'exact_affected_receipt')
            report.update(receipt_verified=True, methods_verified=1, cases_verified=expected['cases'],
                          full_method_ast_compiled=True)
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
        (not args.run_host or report['receipt_verified']))
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
