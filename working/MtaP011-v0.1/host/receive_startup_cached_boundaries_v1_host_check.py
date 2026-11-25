"""Default pure SOURCE proof; one explicit affected private-cache HOST method.

Only --run-host starts the new narrow fixture, using frozen private snapshots.
This is not P011 timing, real clock/IO, close, no-RF startup or phone acceptance.
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
SELF = 'host/receive_startup_cached_boundaries_v1_host_check.py'
CMD = 'HOST_MTA_RECEIVE_STARTUP_CACHED_BOUNDARIES_V1_CONTRACT.cmd'
TEST = 'tests/test_receive_startup_cached_boundaries_v1.py'
SELECTOR = 'ReceiveStartupCachedBoundariesV1Contract.test_original_check_trace_and_passive_cache'
SCENARIOS = 47
PINS = (
    ('host/receive_startup_cached_boundaries_v1_projection.py', 8772,
     '20995f25a43834f8f30b80b74f5730d4707656355e5afc6b78b23a7a923b792b'),
    ('host/device_receive_startup_cached_boundaries_v1_check.py', 7113,
     'be7f918b520b9f03c14efb1d451e9a0c589514022cc8b5f8a11d8f1b83a292b4'),
    ('host/device_receive_publication_progress_v1_startup_check.py', 18494,
     'f47479a85dd54dd1e192509dfe125d1da336edae20a4cd607fa24e5cca02dadf'),
    ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_receive_factory.py', 99257,
     '5fd3e85df3f76a48220564bdc96a429cfa2da513ee528d8745987f0d176eda01'),
    (TEST, 12253, '052afba0648e22e5278ef73dc10f61103ea7c0159ed339ea65b17e87b72eff2c'),
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'))
README = (b'One affected private-cache HOST method. Actual selected Factory check_active AST\n'
          b'creates a traceback using explicit Owner/Session/Loader/Factory/clock models.\n'
          b'After seeding, lifecycle and clock seams are traps; no original suite is called.\n'
          b'No P011, real IO/close, startup timing, RF, network, phone or admission is verified.\n'
          b'Nine values are retained samples, not import-only duration or a close receipt.\n'
          b'The PC-only parser never participates in original startup PASS or None Trial policy.\n'
          b'Raw streams, rejected inputs and traceback details remain private.\n')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(name):
    # Same narrow fixed-input gates as the immutable startup mother; Windows
    # path/fd mode differences are handled only by its original identity rule.
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
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else:
            equal = opened == before
        if not equal:
            raise ValueError('fixed_identity')
        raw = handle.read(2097153)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]:
        raise ValueError('fixed_changed')
    return raw


def pure_module(raw, name, path, remove_guard=False):
    tree = ast.parse(raw, feature_version=(3, 5))
    guards = [row for row in tree.body if isinstance(row, ast.If)]
    if remove_guard:
        if len(guards) != 1 or ast.dump(guards[0].test) != ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body):
            raise ValueError('one_fixed_main_guard')
        tree.body.remove(guards[0])
    elif guards:
        raise ValueError('source_guard_forbidden')
    value = types.ModuleType(name)
    value.__file__ = str(BASE / path)
    exec(compile(tree, value.__file__, 'exec'), value.__dict__)
    return value


def source_contract(inputs):
    helper = pure_module(inputs[PINS[0][0]], 'fixed_private_cache_source', PINS[0][0])
    wrapper = pure_module(inputs[PINS[1][0]], 'fixed_private_cache_wrapper', PINS[1][0], True)
    derived = wrapper.derive(inputs[PINS[2][0]])
    function = ast.parse(inputs[PINS[0][0]], feature_version=(3, 5)).body
    function = next(row for row in function if isinstance(row, ast.FunctionDef) and
                    row.name == '_private_startup_cached_boundaries_v1')
    allowed = {'type', 'len', 'isinstance', 'range', 'any', 'tuple', 'zip'}
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            call = node.func
            if not (isinstance(call, ast.Name) and call.id in allowed or
                    isinstance(call, ast.Attribute) and call.attr in ('get', 'append')):
                raise ValueError('passive_projection_call_set')
    assignments = {row.targets[0].id: row.value for row in function.body[1].body
                   if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name)}
    if ast.dump(assignments['before']) != ast.dump(assignments['after']):
        raise ValueError('two_equal_cache_reads')
    fragment = helper.target_fragment(inputs[PINS[0][0]])
    if b'parse_private' in fragment or len(fragment) > 16384:
        raise ValueError('only_target_projection_selected')
    carrier = (b'import types\ncomponent=session.run_fixed(artifacts,False,receive_trial_requested=False)\n'
               b'retained=session._RETAINED\nprint("RESULT="+repr(component))\n')
    current = helper.inject(carrier, inputs[PINS[0][0]])
    if current.replace(b'retained=session._RETAINED\n' + fragment,
                       b'retained=session._RETAINED\n') != carrier:
        raise ValueError('complete_target_inverse')
    test = ast.parse(inputs[TEST], feature_version=(3, 5))
    methods = [row.name for node in test.body if isinstance(node, ast.ClassDef)
               for row in node.body if isinstance(row, ast.FunctionDef) and row.name.startswith('test_')]
    if methods != ['test_original_check_trace_and_passive_cache']:
        raise ValueError('only_one_affected_contract_method')
    return dict(derived_host_bytes=len(derived), derived_host_sha256=sha(derived),
                private_fragment_bytes=len(fragment), private_fragment_sha256=sha(fragment))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    mode = 'host' if args.run_host else 'source'
    out = BASE / 'results' / ('receive-startup-cached-boundaries-v1-' + mode + '-' +
          datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs, sealer, evidence, child = {}, None, None, None
    report = dict(schema='p011-startup-cached-boundaries-v1-affected-contract', mode=mode,
        passed=False, error=None, source_checked=False, source_preserved=False,
        child_invoked=False, host_exit='NOT_RUN', methods_requested=1, scenarios_requested=SCENARIOS,
        methods_verified=None, scenarios_verified=None, selector=SELECTOR, old_methods_run=0,
        actual_check_active_AST_configured=True, lifecycle_traps_configured=True,
        narrow_clock_and_owner_models_configured=True, original_XHR_executed=False,
        runtime_graph_executed=False, real_clock_IO_verified=False, physical_close_verified=False,
        device=False, rf=False, phone=False, original_PASS_changed=False)

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
        sealer = pure_module(raw, 'fixed_private_cache_contract_sealer', seal[0])
        evidence = sealer.InputEvidence(inputs)
        for path, size, digest in PINS[:-1]:
            read(path, (size, digest))
        read(SELF)
        read(CMD)
        facts = source_contract(inputs)
        report.update(facts, source_checked=True, source_count=len(inputs))
        evidence.snapshot(out, lambda name: name)
        if args.run_host:
            report['child_invoked'] = True
            child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST),
                SELECTOR, str(out / 'private-inputs')], cwd=str(out),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            sealer.fresh(private / 'stdout.raw', child.stdout)
            sealer.fresh(private / 'stderr.raw', child.stderr)
            report.update(host_exit=child.returncode, stdout_bytes=len(child.stdout),
                stdout_sha256=sha(child.stdout), stderr_bytes=len(child.stderr), stderr_sha256=sha(child.stderr))
            derived_stdout = child.stdout.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
            if child.returncode != 0 or derived_stdout != (
                    'PRIVATE_CACHE_CONTRACT_SCENARIOS=' + str(SCENARIOS) + '\n'):
                raise ValueError('affected_method_failed')
            report.update(methods_verified=1, scenarios_verified=SCENARIOS)
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
        (not args.run_host or report['methods_verified'] == 1 and report['scenarios_verified'] == SCENARIOS))
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
