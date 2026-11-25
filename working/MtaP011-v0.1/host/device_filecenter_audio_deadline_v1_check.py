"""Default SOURCE; explicit --device checks one actual P011 audio lock/cap case.

No staging, audio playback, Owner, Companion, UI, phone or radio activation.
The caller cleanup cap is tested, not whole-parent deadline enforcement.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_filecenter_audio_deadline_v1_check.py'
CMDS = ('HOST_MTA_FILECENTER_AUDIO_DEADLINE_V1_CHECK.cmd',
        'TEST_MTA_FILECENTER_AUDIO_DEADLINE_V1.cmd')
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/filecenter_audio_deadline_v1_target.py', 11356,
     '8865414ff1a9b1ff7e87ca61949e81deba3cb9477a46df0b6d11e33eda899f42'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045,
     'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def definitions(key, raw):
    module = types.ModuleType('_fixed_' + Path(key).stem)
    module.__file__ = str(BASE / key)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def derived(raw):
    return raw.decode('utf-8', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')


def reply(adb, label, command, prefix, timeout, receipts, data=None):
    try:
        raw = adb.run(label, ['shell', command], timeout=timeout, input_data=data)
    finally:
        stem = '%02d-%s' % (adb.index, label)
        receipt = dict(host_exit=None, remote_exit=None, stderr_bytes=None)
        host = adb.directory / (stem + '.host-exit')
        stderr = adb.directory / (stem + '.stderr.raw')
        stdout = adb.directory / (stem + '.stdout.raw')
        if host.exists():
            exit_text = host.read_text(encoding='ascii')
            receipt['host_exit'] = int(exit_text) if re.fullmatch(r'-?[0-9]+', exit_text) else exit_text
        if stderr.exists():
            receipt['stderr_bytes'] = stderr.stat().st_size
        if stdout.exists():
            matches = re.findall(rb'(?m)^MTA_REMOTE_EXIT=([0-9]+)\r*$', stdout.read_bytes())
            if len(matches) == 1:
                receipt['remote_exit'] = int(matches[0])
        receipts[label] = receipt
    stem = '%02d-%s' % (adb.index, label)
    need((adb.directory / (stem + '.stderr.raw')).read_bytes() == b'', 'remote_stderr')
    lines = derived(raw).splitlines()
    exits = [line for line in lines if line.startswith('MTA_REMOTE_EXIT=')]
    need(exits == ['MTA_REMOTE_EXIT=0'], 'remote_exit')
    rows = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    need(len(rows) == 1, 'remote_result_count')
    value = ast.literal_eval(rows[0])
    need(type(value) is dict, 'remote_result_dict')
    return value


def stock_probe(adb, probe, label, command, receipts):
    value = reply(adb, label, command, 'RESULT=', 70, receipts)
    need(set(value) == {'stock', 'capabilities'}, 'stock_schema')
    stock, cap = value['stock'], value['capabilities']
    need(stock['hashes'] == probe.PINS, 'stock_hashes')
    rows = stock['processes']
    for name in ('Z03', 'control_engine', 'weston'):
        matched = [row for row in rows if row['name'] == name]
        need(len(matched) == 1, 'stock_process_count')
        if name != 'weston':
            need(matched[0]['exe'] == '/usr/bin/' + name and
                 type(matched[0]['parent_identity']) is dict, 'stock_process_identity')
    need(cap['architecture'] == 'armv7l' and cap['python_version'] == (3, 5, 5) and
         cap['temporary_menu_present'] is False, 'fixed_device_baseline')
    return value


def check_case(value, maker):
    need(set(value) == maker.RESULT_FIELDS and value['schema'] == maker.SCHEMA and
         value['python_version'] == (3, 5, 5) and type(value['case_count']) is int and
         value['case_count'] == 1 and type(value['scope']) is dict and
         set(value['scope']) == set(maker.SCOPE) and
         all(value['scope'][key] is expected for key, expected in maker.SCOPE.items()), 'case_schema')
    positives = ('complete', 'original_modules_loaded', 'original_class_methods_unchanged',
        'parent_cap_identity_preserved', 'original_runtime_error_received',
        'snapshot_runtime_error_received', 'passive_pending_received',
        'retry_runtime_error_received', 'old_cleanup_cap_identity_preserved',
        'fixture_holder_released', 'fixture_thread_closed', 'original_stop_finished',
        'empty_audio_actors_closed')
    need(all(value[name] is True for name in positives) and
         value['cleanup_pending'] is False and type(value['tickets']) is int and
         value['tickets'] == 0 and type(value['seam_calls']) is tuple and
         value['seam_calls'] == (0, 0) and
         all(type(item) is int for item in value['seam_calls']), 'case_facts')
    durations = value['durations']
    limits = dict(holder_enter=1.2, initial_stop=0.60, pending_snapshot=0.25,
        passive_closed=0.25, later_cap_retry=0.25, fixture_release_join=2.2,
        released_original_stop=0.60, total=10.0)
    need(type(durations) is dict and set(durations) == set(limits), 'case_duration_fields')
    need(all(type(durations[key]) is float and math.isfinite(durations[key]) and
             0.0 <= durations[key] <= limit for key, limit in limits.items()), 'case_duration_limits')


def run(device):
    # Bootstrap only this fixed, already-read pure sealer; no ADB before snapshot.
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), digest(raw)) == PINS[0][1:], 'sealer_pin')
    seal = definitions(PINS[0][0], raw)
    mode = 'device' if device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('filecenter-audio-deadline-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='p011-filecenter-audio-deadline-v1-parent', mode=mode,
        evidence_level='SOURCE_ONLY', passed=False, checker_exit=1,
        device_attempted=False, target_attempted=False, target_remote_exit=None,
        target_host_exit=None, source_preserved=False, stock_before_ok=False,
        stock_after_ok=False, stock_unchanged=False, wifi_state_unchanged=False,
        rf_activated=False, staging_performed=False, source_methods_modified=False,
        parent_deadline_behavior_verified=False, full_filecenter_deadline_verified=False,
        full_owner_cleanup_verified=False, restoration_verified=False,
        phone_interop='NOT_TESTED', case=None, error=None, command_receipts={})
    adb = probe = before = baseline_command = None
    failure = None
    snapshotted = False
    try:
        for key, size, sha in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, sha))
        for key in (SELF,) + CMDS:
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        snapshotted = True
        maker = definitions(PINS[2][0], inputs[PINS[2][0]])
        need(maker.PINS == PINS[3:], 'maker_original_pins')
        target = maker.make_source({row[0]: inputs[row[0]] for row in maker.PINS})
        need(type(target) is bytes and len(target) <= 48000 and
             max(map(len, target.splitlines())) <= 256, 'target_budget')
        ast.parse(target.decode('ascii'), feature_version=(3, 5))
        seal.fresh(out / 'private-raw/target.py', target)
        probe = definitions(PINS[1][0], inputs[PINS[1][0]])
        baseline = probe.source().encode('utf-8')
        payload = base64.b64encode(zlib.compress(baseline)).decode('ascii')
        baseline_command = ('/usr/bin/python3.5 -I -B -c "import signal,base64,zlib;signal.alarm(60);'
            'exec(zlib.decompress(base64.b64decode(\'' + payload + '\')))"; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        need(len(baseline_command) <= 3500, 'baseline_inline_budget')
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(30);'
            'exec(sys.stdin.buffer.read(' + str(len(target)) + '))" p011-filecenter-audio-deadline-v1; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        seal.fresh(out / 'private-raw/commands.txt',
                   (baseline_command + '\n' + command + '\n').encode('ascii'))
        report.update(input_count=len(inputs), input_bytes=sum(map(len, inputs.values())),
            target_bytes=len(target), target_sha256=digest(target),
            target_max_line=max(map(len, target.splitlines())), target_alarm_seconds=30,
            target_host_timeout_seconds=45, baseline_alarm_seconds=60,
            baseline_host_timeout_seconds=70, alarm_before_stdin=True,
            input_pins=[dict(path=key, bytes=len(value), sha256=digest(value))
                        for key, value in inputs.items()])
        if device:
            # Re-enumeration selects one current explicit P011, never the emulator.
            adb = probe.Adb(out / 'private-raw')
            report['device_attempted'] = True
            before = stock_probe(adb, probe, 'stock-before', baseline_command, report['command_receipts'])
            report['stock_before_ok'] = True
            report['target_attempted'] = True
            value = reply(adb, 'audio-lock-case', command, maker.RESULT_PREFIX, 45,
                          report['command_receipts'], target)
            check_case(value, maker)
            report.update(case=value, evidence_level='P011_ACTUAL_AUDIO_METHOD_REAL_LOCK')
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if report['device_attempted']:
            try:
                after = stock_probe(adb, probe, 'stock-after', baseline_command, report['command_receipts'])
                report['stock_after_ok'] = True
                if before is not None:
                    report['stock_unchanged'] = before['stock'] == after['stock']
                    report['wifi_state_unchanged'] = (before['capabilities']['wifi_connected'] is
                                                     after['capabilities']['wifi_connected'])
                    need(report['stock_unchanged'] and report['wifi_state_unchanged'], 'baseline_changed')
            except BaseException as error:
                seal.fresh(out / 'private-raw/after-stock-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None:
                    failure = error
        try:
            for key, expected in tuple(inputs.items()):
                actual = evidence.read(BASE / key, key=key)
                need(actual == expected, 'source_changed')
            report['source_preserved'] = True
        except BaseException as error:
            seal.fresh(out / 'private-raw/after-source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None:
                failure = error
        try:
            if not snapshotted or evidence.partial or evidence.changed_attempts:
                evidence.snapshot(out / 'private-final-evidence' if snapshotted else out, lambda key: key)
        except BaseException as error:
            seal.fresh(out / 'private-raw/snapshot-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None:
                failure = error
        target_receipt = report['command_receipts'].get('audio-lock-case', {})
        report['target_host_exit'] = target_receipt.get('host_exit')
        report['target_remote_exit'] = target_receipt.get('remote_exit')
        if failure is None:
            report.update(passed=True, checker_exit=0)
        else:
            report['error'] = type(failure).__name__
    readme = ("Default SOURCE is PC-only; --device executes one actual unmodified audio-method real-lock case.\n"
        "Caller cleanup cap only: original RuntimeError, bounded snapshot/passive query/retry, no cap renewal, fixture closes.\n"
        "Parent-cap identity is not parent deadline behavior. Full FileCenter/Companion/Owner/physical audio remain unverified.\n"
        "No play, process launch, HTTP, RF, UI, staging, user-file or system modification requested by the case.\n"
        "Stock and Wi-Fi comparisons are limited observations, not full recovery. Phone interop NOT_TESTED.\n"
        "Raw streams, exceptions and complete input/source snapshots remain private; ZIP has only these two public members.\n").encode('ascii')
    sealed = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        evidence_level=sealed['report']['evidence_level'], error=sealed['report']['error'],
        result_dir=str(out), result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', action='store_true', help='explicit limited P011 real-lock check')
    return run(parser.parse_args().device)


if __name__ == '__main__':
    sys.exit(main())
