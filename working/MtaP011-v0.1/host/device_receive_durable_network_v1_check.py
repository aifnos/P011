"""Default SOURCE; --device is one finite P011 real loopback fault test.

Current runtime bytes stay intact. Only new synthetic volatile files and
loopback sockets are requested, never native RF, UI, user or system files.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import math
from pathlib import Path
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_durable_network_v1_check.py'
MAKER = 'host/receive_durable_network_v1_target.py'
MAKER_PIN = (27242, '2131525735fc6d021e061280c1191b5cc6e0a6212e3a0bb5b802e68e08e11e74')
CMDS = ('HOST_MTA_P011_DURABLE_NETWORK_V1_CHECK.cmd',
        'TEST_MTA_P011_DURABLE_NETWORK_V1.cmd')
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/device_filecenter_audio_deadline_v1_check.py', 13753,
     '69f7c6d4b192f1ab7a7c75101a6583d31773141e007b7f33c5ba2e457763d71c'),
    ('host/formal_receive_scope_dispatch_v1_private_source_manifest.json', 8168,
     '52f0360b3fb0138b8fa6fd5589bb2d9f29e68d47e601e6d63ff5ebf60e3942ca'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def definition(key, raw):
    value = types.ModuleType('_p011_durable_' + Path(key).stem)
    value.__file__ = str(BASE / key)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def validate(value, maker):
    fixed = maker.RESULT_FIXED
    need(type(fixed) is dict and 'phase_elapsed_seconds' not in fixed and
         type(value) is dict and set(value) == set(fixed) | {'phase_elapsed_seconds'}, 'result_fields')
    def exact(left, right):
        if type(left) is not type(right): return False
        if type(right) is tuple:
            return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
        return left == right
    need(all(exact(value[key], expected) for key, expected in fixed.items()), 'fixed_result_facts')
    elapsed = value['phase_elapsed_seconds']
    need(type(elapsed) is tuple and len(elapsed) == 2 and
         all(type(item) is float and math.isfinite(item) and 0 <= item <= 35.0
             for item in elapsed), 'phase_durations')


def run(device):
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), sha(raw)) == PINS[0][1:], 'sealer_pin')
    seal = definition(PINS[0][0], raw)
    mode = 'device' if device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('p011-durable-network-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}; evidence = seal.InputEvidence(inputs)
    report = dict(schema='p011-durable-network-v1-parent', mode=mode, passed=False,
        device_attempted=False, target_attempted=False, observation=None,
        source_preserved=False, snapshot_preserved=False, actual_selected_lowlevel_match=False,
        stock_before_ok=False, stock_after_ok=False, limited_stock_unchanged=False,
        wifi_state_unchanged=False, synthetic_volatile_writes_requested=False,
        loopback_sockets_requested=False, rf=False, native_admission=False,
        native_owner=False, full_bridge=False, ui=False, staging=False,
        graph_changed=False, user_files_accessed=False, full_restore_verified=False,
        phone=False, error=None, command_receipts={})
    adb = probe = helper = before = baseline_command = None
    failure = None; snapshotted = False
    try:
        need(type(MAKER_PIN) is tuple and len(MAKER_PIN) == 2, 'maker_not_frozen')
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        evidence.read(BASE / MAKER, key=MAKER, pin=MAKER_PIN)
        maker = definition(MAKER, inputs[MAKER])
        need(type(maker.PINS) is tuple and len(maker.PINS) == 10, 'maker_sources')
        for key, size, pin in maker.PINS:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF,) + CMDS:
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key); snapshotted = True
        current = json.loads(inputs[PINS[3][0]])
        for module, path in (('mta_transport', 'candidate/formal-receive-durable-state-v1/runtime/mta_transport.py'),
                             ('mta_storage', 'candidate/formal-receive-durable-state-v1/runtime/mta_storage.py')):
            rows = [row for row in current['sources'] if row['module'] == module]
            need(len(rows) == 1 and rows[0]['path'] == path and rows[0]['bytes'] == len(inputs[path]) and
                 rows[0]['sha256'] == sha(inputs[path]), 'actual_lowlevel_sources')
        report['actual_selected_lowlevel_match'] = True
        target = maker.make_source({row[0]: inputs[row[0]] for row in maker.PINS})
        need(type(target) is bytes and len(target) <= 2097152 and
             max(map(len, target.splitlines())) <= 256, 'target_budget')
        ast.parse(target.decode('ascii'), feature_version=(3, 5))
        seal.fresh(out / 'private-raw/target.py', target)
        probe = definition(PINS[1][0], inputs[PINS[1][0]])
        helper = definition(PINS[2][0], inputs[PINS[2][0]])
        packed = base64.b64encode(zlib.compress(probe.source().encode('utf-8'))).decode('ascii')
        baseline_command = ('/usr/bin/python3.5 -I -B -c "import signal,base64,zlib;signal.alarm(60);'
            'exec(zlib.decompress(base64.b64decode(\'' + packed + '\')))"; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(80);'
            'exec(sys.stdin.buffer.read(' + str(len(target)) + '))" p011-durable-network-v1; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        need(len(baseline_command) <= 3500, 'baseline_command_limit')
        seal.fresh(out / 'private-raw/commands.txt', (baseline_command + '\n' + command + '\n').encode('ascii'))
        report.update(input_count=len(inputs), target_bytes=len(target), target_sha256=sha(target),
            target_max_line=max(map(len, target.splitlines())), phase_active_seconds=30,
            phase_cleanup_seconds=5, target_alarm_seconds=80,
            target_host_timeout_seconds=95, alarm_before_stdin=True)
        if device:
            adb = probe.Adb(out / 'private-raw'); report['device_attempted'] = True
            before = helper.stock_probe(adb, probe, 'stock-before', baseline_command, report['command_receipts'])
            report['stock_before_ok'] = True
            report.update(target_attempted=True, synthetic_volatile_writes_requested=True,
                          loopback_sockets_requested=True)
            value = helper.reply(adb, 'durable-network-case', command, 'P011_DURABLE_NETWORK=', 95,
                                 report['command_receipts'], target)
            validate(value, maker); report['observation'] = value
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            try:
                after = helper.stock_probe(adb, probe, 'stock-after', baseline_command, report['command_receipts'])
                report['stock_after_ok'] = True
                if before is not None:
                    report['limited_stock_unchanged'] = before['stock'] == after['stock']
                    report['wifi_state_unchanged'] = before['capabilities']['wifi_connected'] is after['capabilities']['wifi_connected']
                    need(report['limited_stock_unchanged'] and report['wifi_state_unchanged'], 'baseline_changed')
            except BaseException as error:
                seal.fresh(out / 'private-raw/after-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None: failure = error
        try:
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected, 'source_changed')
                if snapshotted:
                    need((out / 'private-inputs' / key).read_bytes() == expected, 'snapshot_changed')
            report['source_preserved'] = True; report['snapshot_preserved'] = snapshotted
        except BaseException as error:
            seal.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        if not snapshotted or evidence.partial or evidence.changed_attempts:
            try: evidence.snapshot(out / 'private-final-evidence' if snapshotted else out, lambda key: key)
            except BaseException as error:
                seal.fresh(out / 'private-raw/snapshot-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None: failure = error
        if failure is None: report['passed'] = True
        else: report['error'] = type(failure).__name__
    sealed = seal.seal_result(out, report, b'Current-source P011 real loopback TLS/HTTP/durable-storage fault test only with --device.\nTwo synthetic fresh volatile trees, original bytes/CRC/fsync and cleanup; no user or system writes.\nLoopback admission/socket owner are explicit fixtures, not native interface or full Bridge.\nLate cancellation and missing peer ACK are never transfer success.\nNo RF, UI, phone, graph generation or Stage; finite alarm precedes stdin.\nRaw dual streams, remote/host exits, sources and snapshots stay private.\n')
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        error=sealed['report']['error'], result_dir=str(out), result_zip=str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', action='store_true')
    raise SystemExit(run(parser.parse_args().device))
