"""PC SOURCE-only Receiver FileCenter adaptation check, never a graph run.

Checks the two actual Owner sources and the fixed close-seal method source.
No import, Owner construction, HTTP, ADB, UI, wireless or phone activity.
"""
import argparse
import ast
import copy
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_filecenter_owner_v1_source_check.py'
CMD = 'TEST_MTA_RECEIVE_FILECENTER_OWNER_V1_SOURCE.cmd'
OLD = 'candidate/formal-receive-ui-v1/runtime/mta_client_service_owner.py'
NEW = 'candidate/formal-receive-filecenter-owner-v1/runtime/mta_client_service_owner.py'
SEAL = 'candidate/filecenter-close-seal-v1/runtime/mta_client_service_owner.py'
INPUTS = (
    (OLD, 78661, '4eb75d7ee5c8f800b4ea8f31dbdac38edd36bc56a36bb11e7f7ef4519dbc60fb'),
    (NEW, 107037, '6eb891d71b5e935c6bbfdaf4a19621889cdf7c7ee5c56fcd4bcc08f89473f5a2'),
    (SEAL, 90745, '9341ffdf01bd9927384ad78a9c824b3f7c42a29ffdbe19858b9bbba14c1826f8'))
ALLOWED_CHANGED = frozenset(('__init__', '_context', 'start', 'close',
    '_close_directories', '_closed', 'status'))
FILECENTER_METHODS = frozenset(('create_filecenter', '_filecenter_definitions_current',
    '_filecenter_current', '_capture_filecenter_partial', '_filecenter_partial_current',
    '_close_filecenter', '_filecenter_closed'))


def sha(raw): return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True: raise ValueError(code)


def dump(node): return ast.dump(node, include_attributes=False)


def methods(tree):
    cls = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedStateServiceOwner']
    need(len(cls) == 1, 'owner_class')
    result = {row.name: row for row in cls[0].body if isinstance(row, ast.FunctionDef)}
    need(len(result) == len(cls[0].body), 'owner_method_shape')
    return result


def literal(tree, name):
    values = [row.value for row in tree.body if isinstance(row, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
    need(len(values) == 1, 'single_literal')
    return ast.literal_eval(values[0])


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle: need(handle.write(raw) == len(raw), 'record_write')
    need(path.read_bytes() == raw, 'record_readback')


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    out = BASE / 'results' / ('receive-filecenter-owner-v1-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    originals = {}
    report = dict(kind='receiver_filecenter_owner_source_adaptation', source_only=True,
        passed=False, source_unchanged=False, source_preserved=False, changed_methods=[],
        added_methods=[], parent_original_methods_preserved=False,
        fixed_literal_preserved=False, projected_payload_bytes=None,
        projection_only=True, payload_role_count_changed=False,
        filecenter_packaged=False, filecenter_worker_wired=False,
        original_graph_executed=False, owner_constructed=False,
        adb=False, device=False, rf=False, ui=False, phone=False, error_code=None)
    try:
        for path, size, digest in INPUTS:
            need(type(size) is int and type(digest) is str, 'source_freeze_pending')
            raw = (BASE / path).read_bytes()
            need((len(raw), sha(raw)) == (size, digest), 'input_pin')
            originals[path] = raw
        for path in (SELF, CMD): originals[path] = (BASE / path).read_bytes()
        trees = {path: ast.parse(raw, filename=path, feature_version=(3, 5))
            for path, raw in originals.items() if path.endswith('.py')}
        before, after = methods(trees[OLD]), methods(trees[NEW])
        need(set(before) <= set(after), 'parent_method_removed')
        changed = sorted(name for name in before if dump(before[name]) != dump(after[name]))
        added = sorted(set(after) - set(before))
        need(set(changed) <= ALLOWED_CHANGED, 'unrelated_parent_method_changed')
        need(FILECENTER_METHODS <= set(added), 'filecenter_methods_missing')
        need(all(name in FILECENTER_METHODS or name == '_seal_filecenter_directories' or name.startswith('_filecenter_') or
            name.startswith('_capture_filecenter_') for name in added), 'unrelated_method_added')
        need([arg.arg for arg in after['create_filecenter'].args.args] ==
            ['self', 'source_rows', 'owner_module'], 'actual_owner_module_argument')
        for name in ('ROOT', 'USER_ROOT', 'BOOT_PATH', 'BOOT_PIN', 'BOOT_MODULES',
                     'GO_ASSET_RUNTIME', 'HELPER_PINS', 'CLEANUP_SECONDS', 'MAX_REQUESTS'):
            # ROOT expressions are deliberately unevaluated and compared as AST.
            old_rows = [row for row in trees[OLD].body if isinstance(row, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
            new_rows = [row for row in trees[NEW].body if isinstance(row, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
            need(len(old_rows) == len(new_rows) == 1 and dump(old_rows[0]) == dump(new_rows[0]),
                 'fixed_literal_changed')
        need(literal(trees[NEW], 'FILECENTER_PINS') == literal(trees[SEAL], 'FILECENTER_PINS'),
             'isolated_filecenter_pins_changed')
        need(literal(trees[NEW], 'FILECENTER_MAX_SOURCE') == 131072, 'filecenter_budget_changed')
        for name in ('_filecenter_current', '_filecenter_partial_current', '_filecenter_closed'):
            need(dump(after[name]) == dump(methods(trees[SEAL])[name]), 'seal_consumer_changed')
        close = copy.deepcopy(after['_close_filecenter'])
        prefix = ast.parse('self._context()\nif self.cleanup_until is not self._cleanup_until_original: '
                           "_fail('cleanup_cap_changed')\n").body
        need([dump(row) for row in close.body[:2]] == [dump(row) for row in prefix], 'original_cleanup_cap_guard')
        close.body = close.body[2:]
        need(dump(close) == dump(methods(trees[SEAL])['_close_filecenter']), 'close_consumer_changed')
        report['projected_payload_bytes'] = 4129184 + len(originals[NEW]) - len(originals[OLD])
        need(report['projected_payload_bytes'] <= 4 * 1024 * 1024, 'payload_projection_budget')
        report.update(changed_methods=changed, added_methods=added,
            parent_original_methods_preserved=True, fixed_literal_preserved=True)
    except BaseException as error:
        report['error_code'] = str(error) if type(error) is ValueError else type(error).__name__
    finally:
        report['source_unchanged'] = bool(originals) and all(
            (BASE / path).read_bytes() == raw for path, raw in originals.items())
        for path, raw in originals.items(): write_new(out / 'private-inputs' / path, raw)
        report['source_preserved'] = bool(originals) and all(
            (out / 'private-inputs' / path).read_bytes() == raw for path, raw in originals.items())
    report['passed'] = (report['error_code'] is None and report['source_unchanged'] is True and
        report['source_preserved'] is True and report['parent_original_methods_preserved'] is True and
        report['fixed_literal_preserved'] is True)
    outputs = {
        'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({path: dict(bytes=len(raw), sha256=sha(raw))
            for path, raw in originals.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'SOURCE ONLY. Parses exact sources; never imports or executes a runtime graph.\n'
            b'Checks unchanged parent methods/literals, explicit retained Owner-module input and seal-consumer bodies.\n'
            b'4 MiB figure is a projection with unchanged other payloads, not an assembled manifest.\n'
            b'FileCenter pins remain un-packaged and UI worker is not wired in this patch.\n'
            b'No full Owner, startup, guardian, ABI, P011, UI, restoration or phone-transfer PASS.\n')}
    for name, raw in outputs.items(): write_new(out / name, raw)
    archive = out / 'SOURCE_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        need(bundle.testzip() is None and set(bundle.namelist()) == set(outputs) and
            all(bundle.read(name) == raw for name, raw in outputs.items()), 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_sha256=sha(archive.read_bytes()), error_code=report['error_code']), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
