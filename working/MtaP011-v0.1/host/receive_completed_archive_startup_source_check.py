"""SOURCE-only correction audit. Reuse passed HOST originals; run no tests."""
import ast
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
ARCHIVE = 'candidate/receive-completed-archive-v1/runtime/mta_receive_completed_archive.py'
OWNER = 'candidate/receive-completed-archive-v1/runtime/mta_client_service_owner.py'
TEST = 'tests/test_receive_completed_archive.py'
CHECKER = 'host/receive_completed_archive_host_check.py'
CMD = 'HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_CHECK.cmd'
SELF = 'host/receive_completed_archive_startup_source_check.py'
SOURCE_CMD = 'HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_SOURCE_CHECK.cmd'
PRIOR = 'results/receive-completed-archive-host-20261004-172648-16d8865d/'
INPUTS = (ARCHIVE, OWNER, TEST, CHECKER, CMD, SELF, SOURCE_CMD,
    PRIOR + 'private-inputs/' + ARCHIVE, PRIOR + 'private-inputs/' + OWNER,
    PRIOR + 'private-inputs/' + TEST, PRIOR + 'private-inputs/' + CHECKER,
    PRIOR + 'result.json', PRIOR + 'stdout.raw', PRIOR + 'stderr.raw',
    PRIOR + 'child-exit.raw', PRIOR + 'host-exit.raw', PRIOR + 'remote-exit.raw')
PINS = {
    ARCHIVE: (41932, 'fef9d58f9d8359e8407500c9d461a1842e52f6e90cf2d670c2c0088a92d888ca'),
    OWNER: (80798, 'f9ef01ed2ecf95b13bba3627e7e810e097f75ed30e8ef470b51a2353fd874bab'),
    TEST: (22365, '7fe5c8fed450bdda78f1ddfef57eb62106f04e119370e212eafd3af1fb9b631c'),
    PRIOR + 'private-inputs/' + ARCHIVE:
        (41822, '07d03d9484a7feb5a8d64211a5930b1e1a58dd956d778821a6e0b0d9d2815098'),
    PRIOR + 'private-inputs/' + TEST:
        (22365, '5acbb980ebfdc141c039737b27e1e2e7f8868e13f136e27a347707593fafc255'),
    PRIOR + 'private-inputs/' + CHECKER:
        (8477, 'e65b18cbd133a9d927536d5eda607a733cd04ec0d853e96b2be98764af4d2b09'),
}


def digest(raw): return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('readback')


def ast_key(node): return ast.dump(node, include_attributes=False)


def parse(raw): return ast.parse(raw, feature_version=(3, 5))


def without_pin_assignment(tree):
    value = copy.deepcopy(tree)
    value.body = [node for node in value.body if not (isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == 'PINS' for target in node.targets))]
    return value


class RemoveOnlyNewStartupPrerequisite(ast.NodeTransformer):
    """Remove the exact two added refuses, never normalize other business AST."""
    def __init__(self): self.count = 0
    def visit_BoolOp(self, node):
        self.generic_visit(node)
        gate = ast_key(ast.parse('owner._startup_closed() is not True', mode='eval').body)
        values = []
        for value in node.values:
            if isinstance(node.op, ast.Or) and ast_key(value) == gate:
                self.count += 1
            else:
                values.append(value)
        node.values = values
        return node


def main():
    if sys.argv[1:]: raise ValueError('fixed_SOURCE_only')
    out = BASE / 'results' / ('receive-completed-archive-startup-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-completed-archive-startup-source-v1', passed=False,
        host_exit=None, remote_exit=None, new_methods=0, old_methods=0,
        prior_host_evidence_reused=False, admin_business_ast_unchanged=False,
        prior_model_method_ast_unchanged=False, checker_only_pin_change=False,
        constructor_consumer_prerequisites_added=0, python35_ast=False,
        actual_production_consumer_tested=False, whole_owner_tested=False,
        boot_sealed=False, archive_policy_default=False,
        device=False, phone=False, rf=False, historical_client_entries_examined=0,
        native_restore_grant=False, restoration_verified=False, error=None)
    sources = {}
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes(); sources[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
            if name in PINS and (len(raw), digest(raw)) != PINS[name]: raise ValueError('fixed_source_pin')
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        prior = json.loads(sources[PRIOR + 'result.json'])
        if (prior['passed'] is not True or prior['child_exit'] != 0 or prior['host_exit'] != 0 or
                prior['remote_exit'] is not None or prior['contracts'] != 16 or
                prior['new_methods'] != 1 or prior['old_methods'] != 0 or
                sources[PRIOR + 'child-exit.raw'] != b'0\n' or sources[PRIOR + 'host-exit.raw'] != b'0\n' or
                sources[PRIOR + 'remote-exit.raw'] != b'NOT_RUN_HOST_ONLY\n'):
            raise ValueError('prior_host_originals')
        for kind in ('stdout', 'stderr'):
            raw = sources[PRIOR + kind + '.raw']
            if (len(raw), digest(raw)) != (prior[kind + '_bytes'], prior[kind + '_sha256']):
                raise ValueError('prior_raw_originals')
        report['prior_host_evidence_reused'] = True
        old_tree, tree = parse(sources[PRIOR + 'private-inputs/' + ARCHIVE]), parse(sources[ARCHIVE])
        normalizer = RemoveOnlyNewStartupPrerequisite()
        normalized = normalizer.visit(copy.deepcopy(tree))
        if normalizer.count != 2 or ast_key(normalized) != ast_key(old_tree):
            raise ValueError('unexpected_business_ast_change')
        report['constructor_consumer_prerequisites_added'] = normalizer.count
        report['admin_business_ast_unchanged'] = True
        if ast_key(without_pin_assignment(parse(sources[TEST]))) != ast_key(
                without_pin_assignment(parse(sources[PRIOR + 'private-inputs/' + TEST]))):
            raise ValueError('model_method_changed')
        report['prior_model_method_ast_unchanged'] = True
        if ast_key(without_pin_assignment(parse(sources[CHECKER]))) != ast_key(
                without_pin_assignment(parse(sources[PRIOR + 'private-inputs/' + CHECKER]))):
            raise ValueError('checker_business_changed')
        report['checker_only_pin_change'] = True
        if sources[OWNER] != sources[PRIOR + 'private-inputs/' + OWNER]:
            raise ValueError('owner_changed')
        owner_tree = parse(sources[OWNER])
        owner_class = next(node for node in owner_tree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedStateServiceOwner')
        ctor = next(node for node in owner_class.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        params = dict(zip((arg.arg for arg in ctor.args.args[-len(ctor.args.defaults):]), ctor.args.defaults))
        if ast.literal_eval(params['archive_completed_receives']) is not False:
            raise ValueError('archive_policy_changed')
        boot_pin = next(ast.literal_eval(node.value) for node in owner_tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'BOOT_PIN' for target in node.targets))
        if boot_pin != (0, 'UNSEALED_RECEIVE_COMPLETED_ARCHIVE_SOURCE_ONLY'):
            raise ValueError('draft_boot_boundary_changed')
        report['python35_ast'] = True
        report['source_count'] = len(sources)
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
        if not report['source_preserved']: raise ValueError('source_changed_during_check')
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'SOURCE ONLY: zero new/old HOST methods, no target module import/execution. '
        b'Exactly two mandatory original-startup-closure prerequisites were added to '
        b'the pure constructor and retained-original consumer before administrative mutation. '
        b'All other production AST, previous administrative IO model method and checker '
        b'business AST remain equal to the preserved passing HOST originals. Updated model '
        b'pins are mechanical. This does not execute/authenticate the production consumer, '
        b'Owner, startup scope, Linux/ARM, P011, phone, RF, history or restore. '
        b'Boot remains explicitly UNSEALED and archive policy default false. '
        b'Private source/raw snapshots are excluded from this public scalar ZIP.\n')
    save(out / 'result.json', result); save(out / 'README.txt', note)
    save(out / 'stdout.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    save(out / 'stderr.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    save(out / 'host-exit.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    save(out / 'remote-exit.raw', b'NOT_INVOKED_SOURCE_ONLY\n')
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
