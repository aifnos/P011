"""PC-only strict derived readback of one retained actual P011 model result.

Never re-executes the model, original checker, device, ADB or old tests.
The original DEVICE parent FAIL is retained; this result validates existing raw.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_trace_overhead_retained_v1_check.py'
PARENT = 'host/device_receive_trace_overhead_v1_check.py'
ORIGINAL = BASE / 'results/receive-trace-overhead-v1-device-model-20261006-175454-814f0725'
OLD_PARENT_PIN = (29547, '0a55ed3e56345fd8aa0214897833eb2df88c04748f4a36a6d78590188cf11e18')
ORIGINAL_ZIP_SHA = '560c348fa9c3fc0db92558b693306be69e0dbe4fae3dec757573dcaafd8d169d'
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/device_filecenter_audio_deadline_v1_check.py', 13753,
     '69f7c6d4b192f1ab7a7c75101a6583d31773141e007b7f33c5ba2e457763d71c'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def definitions(path, raw):
    module = types.ModuleType('_trace_retained_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def main():
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), digest(raw)) == PINS[0][1:], 'sealer_pin')
    seal = definitions(BASE / PINS[0][0], raw)
    out = BASE / 'results' / ('receive-trace-overhead-v1-retained-readback-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='p011-receive-trace-overhead-retained-v1-host', passed=False,
        evidence_level='HOST_DERIVED_FROM_RETAINED_P011_RAW', error=None,
        original_device_parent_passed=False, original_device_parent_error=None,
        original_device_parent_unchanged=False, original_device_input_count=0,
        exact_source_echo=False, raw_device_model_passed=False,
        device_reexecuted=False, adb_invoked=False, old_main_called=False,
        old_tests_replayed=0, graph_loaded=False, rf=False, ui=False, phone_interop=False,
        real_trial_owner_executed=False, startup_performance_verified=False,
        full_restore_verified=False, source_preserved=False, observation=None,
        group_comparison=None, actual_command_receipts=None)
    original_inputs = {}
    original_receipts = None
    try:
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF, PARENT):
            evidence.read(BASE / key, key=key)
        parent = definitions(BASE / PARENT, inputs[PARENT])
        before = {}
        for name in ('result.json', 'README.txt', 'public-result.zip',
                     'private-raw/target.py', 'private-raw/commands.txt'):
            key = 'retained/' + name
            before[name] = evidence.read(ORIGINAL / name, key=key)
        need(digest(before['public-result.zip']) == ORIGINAL_ZIP_SHA, 'original_zip_sha')
        old_report = json.loads(before['result.json'])
        need(old_report['passed'] is False and old_report['error'] == 'ValueError:model_envelope' and
             old_report['input_count'] == 7 and old_report['source_preserved'] is True and
             all(old_report[key] is True for key in ('stock_before_ok', 'stock_after_ok',
                 'limited_stock_unchanged', 'wifi_state_unchanged')), 'original_result')
        report['original_device_parent_error'] = old_report['error']
        for row in old_report['input_pins']:
            key = row['path']
            value = evidence.read(ORIGINAL / 'private-inputs' / key,
                key='retained-inputs/' + key, pin=(row['bytes'], row['sha256']))
            need(row['complete'] is True, 'original_input_partial')
            original_inputs[key] = value
            if key != PARENT:
                need((BASE / key).read_bytes() == value, 'unrelated_input_changed')
        need(len(original_inputs) == 7 and
             (len(original_inputs[PARENT]), digest(original_inputs[PARENT])) == OLD_PARENT_PIN,
             'original_parent_pin')
        old_parent = definitions(ORIGINAL / 'private-inputs' / PARENT, original_inputs[PARENT])
        old_text = original_inputs[PARENT].decode('ascii').replace('\r\n', '\n')
        new_text = inputs[PARENT].decode('ascii').replace('\r\n', '\n')
        old_parser = "    lines = raw.decode('ascii').replace('\\r\\r\\n', '\\n').replace('\\r\\n', '\\n').splitlines()\n"
        new_parser = ("    text = raw.decode('ascii').replace('\\r\\r\\n', '\\n').replace('\\r\\n', '\\n')\n"
            "    # ADB's PTY may echo the complete stdin source. Accept only that exact\n"
            "    # previously supplied source prefix; never discard arbitrary extra output.\n"
            "    echo = target.decode('ascii')\n"
            "    if text.startswith(echo):\n"
            "        text = text[len(echo):]\n"
            "    lines = text.splitlines()\n")
        need(new_text.count(new_parser) == 1 and
             new_text.replace(new_parser, old_parser, 1) == old_text, 'parser_only_inverse')
        old_tree, new_tree = ast.parse(original_inputs[PARENT]), ast.parse(inputs[PARENT])
        old_functions = [node for node in old_tree.body
            if isinstance(node, ast.FunctionDef) and node.name != 'model_reply']
        new_functions = [node for node in new_tree.body
            if isinstance(node, ast.FunctionDef) and node.name != 'model_reply']
        need([ast.dump(node, include_attributes=False) for node in old_functions] ==
             [ast.dump(node, include_attributes=False) for node in new_functions],
             'nonparser_functions_changed')
        need(parent.PINS == old_parent.PINS and parent.BLOCK_EDITS == old_parent.BLOCK_EDITS and
             parent.REMOTE_RUN == old_parent.REMOTE_RUN and parent.ORDER == old_parent.ORDER,
             'target_contract_changed')
        target, derivation = parent.make_target(original_inputs[parent.PINS[3][0]],
            original_inputs[parent.PINS[4][0]])
        need(target == before['private-raw/target.py'] and digest(target) == old_report['target_sha256'],
             'retained_target_changed')
        original_receipts = old_report['command_receipts']
        need(set(original_receipts) == {'stock-before', 'trace-overhead-model', 'stock-after'} and
             all(row['host_exit'] == 0 and row['remote_exit'] == 0 and row['stderr_bytes'] == 0
                 for row in original_receipts.values()), 'actual_exits')
        for index, label in enumerate(('stock-before', 'trace-overhead-model', 'stock-after'), 1):
            for suffix in ('stdout.raw', 'stderr.raw', 'host-exit'):
                name = 'private-raw/%02d-%s.%s' % (index, label, suffix)
                evidence.read(ORIGINAL / name, key='retained/' + name)
                if suffix == 'stderr.raw':
                    need(inputs['retained/' + name] == b'', 'retained_stderr')
                if suffix == 'host-exit':
                    need(inputs['retained/' + name].strip() == b'0', 'retained_host_exit')
        baselines = []
        probe = definitions(BASE / PINS[1][0], inputs[PINS[1][0]])
        for index, label in ((1, 'stock-before'), (3, 'stock-after')):
            key = 'retained/private-raw/%02d-%s.stdout.raw' % (index, label)
            lines = inputs[key].decode('utf-8').replace('\r\r\n', '\n').replace('\r\n', '\n').splitlines()
            marked = [line[7:] for line in lines if line.startswith('RESULT=')]
            need(len(marked) == 1 and [line for line in lines if line.startswith('MTA_REMOTE_EXIT=')] ==
                 ['MTA_REMOTE_EXIT=0'], 'retained_baseline_envelope')
            value = ast.literal_eval(marked[0])
            need(value['stock']['hashes'] == probe.PINS and
                 value['capabilities']['architecture'] == 'armv7l' and
                 value['capabilities']['python_version'] == (3, 5, 5) and
                 value['capabilities']['temporary_menu_present'] is False, 'retained_baseline')
            baselines.append(value)
        need(baselines[0]['stock'] == baselines[1]['stock'] and
             baselines[0]['capabilities']['wifi_connected'] is baselines[1]['capabilities']['wifi_connected'],
             'retained_baseline_changed')
        model_raw = inputs['retained/private-raw/02-trace-overhead-model.stdout.raw']
        normalized = model_raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
        need(normalized.startswith(target.decode('ascii')), 'exact_source_echo')
        tail = [line for line in normalized[len(target):].splitlines() if line]
        need(len(tail) == 2 and tail[0].startswith('TRACE_OVERHEAD_MODEL=') and
             tail[1] == 'MTA_REMOTE_EXIT=0', 'retained_envelope')
        observed = parent.validate(ast.literal_eval(tail[0][len('TRACE_OVERHEAD_MODEL='):]))
        need(observed['passed'] is True, 'actual_model_failed')
        report.update(exact_source_echo=True, raw_device_model_passed=True,
            original_device_input_count=7, observation=observed,
            group_comparison=parent.summary(observed['blocks']),
            actual_command_receipts=original_receipts, derivation=derivation,
            retained_limited_stock_unchanged=True, retained_wifi_state_unchanged=True,
            target_bytes=len(target), target_sha256=digest(target), original_result_zip_sha256=ORIGINAL_ZIP_SHA)
        evidence.snapshot(out, lambda key: key)
        # Original directory and FAIL files remain immutable; no publication back to it.
        need(all((ORIGINAL / name).read_bytes() == value for name, value in before.items()),
             'original_result_changed')
        report['original_device_parent_unchanged'] = True
        for key in (PINS[0][0], PINS[1][0], PINS[2][0], SELF, PARENT):
            need((BASE / key).read_bytes() == inputs[key], 'source_changed')
        report['source_preserved'] = True
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)
        if not (out / 'private-raw/input-read-status.json').exists():
            evidence.snapshot(out, lambda key: key)
    readme = (b'PC-only strict derived readback of one retained actual P011 model; no ADB/model reexecution.\n'
        b'Original DEVICE parent FAIL model_envelope and immutable raw/ZIP retained, not reclassified.\n'
        b'Only exact complete source echo is accepted, followed by one finite model repr and remote0.\n'
        b'Actual unchanged frozen TraceOwner on ordinary selected-check/2000-row generator fixture.\n'
        b'Wall and process CPU separately; no thread CPU, real Trial/Owner/Startup/native admission or phone interop.\n'
        b'Actual prior before/model/after HOST/remote exits and limited baseline facts retained.\n'
        b'Public ZIP only result.json/README.txt; old/new source snapshots and raw remain private.\n')
    sealed = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], error=sealed['report']['error'],
        result_dir=str(out), result_zip=str(sealed['archive']), zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
