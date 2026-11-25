"""PC SOURCE-only navigation delta check and immutable Worker-pin binding.

No runtime import/exec, graph assembly, tests, ADB, UI, HTTP or RF activity.
The bound Worker is an input artifact, not a device or navigation PASS.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_filecenter_navigation_v1_source_check.py'
CMD = 'TEST_MTA_RECEIVE_FILECENTER_NAVIGATION_V1_SOURCE.cmd'
OLD_RUNNER = 'candidate/formal-receive-filecenter-v1/runtime/mta_formal_receive_session.py'
NEW_RUNNER = 'candidate/formal-receive-filecenter-navigation-v1/runtime/mta_formal_receive_session.py'
OLD_WORKER = 'candidate/formal-receive-filecenter-ui-v4/runtime/ui_session.py'
NEW_WORKER = 'candidate/formal-receive-filecenter-navigation-v1/runtime/ui_session.py'
INPUTS = (
    (OLD_RUNNER, 79232, 'c8c4a0cafe08e2f2d269fd08c4b0167978c19e4b752dc01c9687c88c0aaefa1b'),
    (NEW_RUNNER, 85532, 'f7a9552bc368e488a494abefcc32aaf6914d18f06ab667c3a0760e6f344ea212'),
    (OLD_WORKER, 91420, '53465b7cdcd576fa689d5c08e0de38a6c53a360efa76b88563e39f0182382e18'),
    (NEW_WORKER, 95122, '326b8719d01d6d9c94bcc4e308148ec8fe6043d9366d9082a95caedf02bf59af'))
OLD_PIN = "RUNNER_PIN = (79232, 'c8c4a0cafe08e2f2d269fd08c4b0167978c19e4b752dc01c9687c88c0aaefa1b')"
NEW_PIN = "RUNNER_PIN = (85532, 'f7a9552bc368e488a494abefcc32aaf6914d18f06ab667c3a0760e6f344ea212')"
METHOD = 'original_receive_ui_cancelled_empty'
CALLS = frozenset(('type', 'any', 'all', 'getattr', 'len', 'zip',
    'http_ticket.get', 'http_thread.is_alive', 'loader.modules.get',
    'sys.modules.get', 'service.State._receive_trial_exact', 'a.get',
    'threading.Event.is_set'))


def sha(raw): return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True: raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle: need(handle.write(raw) == len(raw), 'record_write')
    need(path.read_bytes() == raw, 'record_readback')


def one(text, start, end):
    # Anchor to the actual indentation, not a suffix of a nested block.
    anchored = '\n' + text
    need(anchored.count('\n' + start) == 1, 'source_start')
    begin = anchored.index('\n' + start)
    need(anchored.count('\n' + end, begin) == 1, 'source_end')
    return text[begin:anchored.index('\n' + end, begin)]


def function(tree, name):
    values = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == name]
    need(len(values) == 1, 'function_shape')
    return values[0]


def literal(tree, name):
    values = [row.value for row in tree.body if isinstance(row, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
    need(len(values) == 1, 'literal_shape')
    return ast.literal_eval(values[0])


def call_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return call_name(node.value) + '.' + node.attr
    raise ValueError('observer_callee')


def local_target(node):
    return (isinstance(node, ast.Name) or isinstance(node, (ast.Tuple, ast.List)) and
        all(local_target(value) for value in node.elts))


def check_observer(tree):
    classes = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedSession']
    need(len(classes) == 1, 'session_shape')
    methods = [row for row in classes[0].body if isinstance(row, ast.FunctionDef) and row.name == METHOD]
    need(len(methods) == 1, 'observer_shape')
    method = methods[0]
    for node in ast.walk(method):
        if isinstance(node, ast.Assign):
            need(all(local_target(target) for target in node.targets), 'observer_field_write')
        need(not isinstance(node, (ast.AugAssign, ast.Delete, ast.Raise, ast.Yield,
                                   ast.YieldFrom, ast.AsyncFunctionDef)), 'observer_effect')
        if isinstance(node, ast.Call): need(call_name(node.func) in CALLS, 'observer_call')
        if isinstance(node, ast.With):
            need(all(call_name(item.context_expr) in ('state.lock', 'trial._lock_original')
                for item in node.items), 'observer_lock')


def check_sources(raws):
    texts = {path: raw.decode('ascii') for path, raw in raws.items() if path in {row[0] for row in INPUTS}}
    trees = {path: ast.parse(text, filename=path, feature_version=(3, 5)) for path, text in texts.items()}
    added = one(texts[NEW_RUNNER], '    def ' + METHOD + '(self):\n', '    def load_owner(self):\n')
    need(len(added.encode('ascii')) == 6300 and
         texts[NEW_RUNNER].replace(added, '', 1) == texts[OLD_RUNNER], 'runner_inverse')
    check_observer(trees[NEW_RUNNER])
    old, new = texts[OLD_WORKER], texts[NEW_WORKER]
    old_run = old[old.index('def run_fixed('):]
    new_run = new[new.index('def run_fixed('):]
    need(one(old_run, '    finally:\n', "    facts['complete'] =") ==
         one(new_run, '    finally:\n', "    facts['complete'] ="), 'finally_changed')
    smoke_start = '            if smoke_only:\n                need(component.original_receive_ui_idle()'
    smoke_end = "                facts['smoke_idle_observed'] = True\n"
    need(one(old_run, smoke_start, smoke_end) + smoke_end ==
         one(new_run, smoke_start, smoke_end) + smoke_end, 'smoke_loop_changed')
    old_tail = one(old_run, '    if smoke_only:\n        # This is original-inventory/Trial DATA only,',
                   '    # Only this scalar allowlist returns.')
    new_tail = one(new_run, '    if smoke_only:\n        # This is original-inventory/Trial DATA only,',
                   '    if navigation_test:\n')
    need(old_tail == new_tail, 'smoke_terminal_changed')
    for path in (OLD_WORKER, NEW_WORKER):
        need(literal(trees[path], 'SMOKE_DISPLAY_SECONDS') == 20, 'display_cap')
    args = function(trees[NEW_WORKER], 'run_fixed').args
    need(args.args[-1].arg == 'navigation_test' and ast.literal_eval(args.defaults[-1]) is False,
         'navigation_default')
    need("need(type(navigation_test) is bool and not (smoke_only and navigation_test), 'navigation_profile')" in new,
         'navigation_strict_bool')
    need('display_until = min(window[5], launched + SMOKE_DISPLAY_SECONDS) if (smoke_only or navigation_test) else window[5]' in new,
         'navigation_display_cap')
    need('getattr(cls, \'original_receive_ui_cancelled_empty\', None) is not method' in new and
         'method.__code__ is not code' in new and 'return method(component) is True' in new,
         'observer_retention')
    need('trial.revoked is True' in added and "trial.revoke_reason == 'cancelled'" in added and
         "trial.reason == 'cancelled'" in added and 'trial.claim_count == 0' in added and
         'trial.session is None' in added and 'state.operation is None and state.session is None' in added and
         'state.wifi_restore_pending is False and state.radio_restore_pending is False' in added and
         'http_thread.is_alive() is not True' in added, 'cancelled_empty_shape')
    need(new.count(OLD_PIN) == 1 and NEW_PIN not in new, 'unbound_pin')
    bound = new.replace(OLD_PIN, NEW_PIN, 1).encode('ascii')
    need(bound.replace(NEW_PIN.encode('ascii'), OLD_PIN.encode('ascii'), 1) == raws[NEW_WORKER],
         'worker_binding_inverse')
    ast.parse(bound.decode('ascii'), filename='bundle/ui_session.py', feature_version=(3, 5))
    return bound


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    out = BASE / 'out' / ('receive-filecenter-navigation-v1-source-' + uuid.uuid4().hex[:24])
    out.mkdir(parents=True, exist_ok=False)
    raws = {}
    report = dict(kind='receive_filecenter_navigation_v1_source', source_only=True, passed=False,
        error_code=None, source_unchanged=False, source_preserved=False,
        runner_inverse=False, old_finally_preserved=False, old_smoke_preserved=False,
        observer_only=False, python35_syntax=False, worker_bound=False, bound_worker=None,
        graph_executed=False, tests_executed=False, device_executed=False,
        payload_75_changed=False, filecenter_9_changed=False, gui_changed=False,
        navigation_device_verified=False, physical_rf_verified=False)
    try:
        for path, size, digest in INPUTS:
            need((BASE / path).stat().st_size == size, 'input_size')
            raw = (BASE / path).read_bytes(); raws[path] = raw
            need(len(raw) == size and sha(raw) == digest, 'input_pin')
        for path in (SELF, CMD):
            raw = (BASE / path).read_bytes(); raws[path] = raw
            need(0 < len(raw) <= 65536, 'driver_size')
        bound = check_sources(raws)
        write_new(out / 'bundle' / 'ui_session.py', bound)
        report.update(runner_inverse=True, old_finally_preserved=True, old_smoke_preserved=True,
            observer_only=True, python35_syntax=True, worker_bound=True,
            bound_worker=dict(path='bundle/ui_session.py', bytes=len(bound), sha256=sha(bound),
                runner_bytes=INPUTS[1][1], runner_sha256=INPUTS[1][2]))
    except BaseException as error:
        report['error_code'] = str(error) if type(error) is ValueError else type(error).__name__
    finally:
        try:
            report['source_unchanged'] = len(raws) == 6 and all(
                (BASE / path).read_bytes() == raw for path, raw in raws.items())
            for path, raw in raws.items(): write_new(out / 'private-inputs' / path, raw)
            report['source_preserved'] = len(raws) == 6 and all(
                (out / 'private-inputs' / path).read_bytes() == raw for path, raw in raws.items())
        except BaseException as error:
            if report['error_code'] is None: report['error_code'] = type(error).__name__
    report['passed'] = (report['error_code'] is None and report['source_unchanged'] is True and
        report['source_preserved'] is True and report['worker_bound'] is True)
    outputs = {
        'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({path: dict(bytes=len(raw), sha256=sha(raw))
            for path, raw in raws.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'SOURCE ONLY. Exact four frozen sources are parsed, never imported or executed.\n'
            b'Checks Runner inverse, unchanged Worker finally/smoke, passive observer and strict bounded navigation profile.\n'
            b'bundle/ui_session.py differs from the frozen navigation Worker only in its Runner pin.\n'
            b'Original inputs and bound source stay outside this metadata-only ZIP. Each run uses a fresh output directory.\n'
            b'No 75-source graph, FC9 or GUI assembly/change; no tests, ADB, UI, service or radio action.\n'
            b'No device/navigation/phone/file/audio/restoration PASS; navigation facts remain distinct from smoke and physical RF.\n')}
    for name, raw in outputs.items(): write_new(out / name, raw)
    archive = out / 'SOURCE_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        need(bundle.testzip() is None and set(bundle.namelist()) == set(outputs) and
             all(bundle.read(name) == raw for name, raw in outputs.items()), 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        bound_worker=report['bound_worker'], zip_sha256=sha(archive.read_bytes()),
        error_code=report['error_code']), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
