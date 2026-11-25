"""Independent bounded CLIENT-history observation. Default PC SOURCE only.

Explicit --read-device performs only fixed-root reads through identified P011
ADB. It never loads service/Owner/Boot, takes locks, repairs, archives or grants
admission. Private snapshots/raw streams may contain journal and actor data.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
DIAGNOSTIC = ('candidate/client-history-readonly-v1/runtime/client_history.py', 8955,
    '5d89fe70957a84e44c3eca5b702bb05402cc17943914a927b6913282f6f419f2')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
SELF = 'host/device_client_history_readonly_v1_check.py'
CMD = 'CHECK_MTA_CLIENT_HISTORY_READONLY_V1.cmd'
CLASSES = ('entry_unknown', 'regular_entry', 'symlink_entry', 'other_entry',
           'run_directory', 'run_unreadable')
FIELDS = frozenset(('reason', 'root_empty', 'root_stable', 'pending', 'entry_count', 'counts',
    'resources_closed', 'full_journal_schema_validated', 'actor_tasks_verified',
    'active_session_verified', 'restoration_verified', 'receive_admission',
    'device_mutations', 'radio_operations', 'private_entries', 'private_pending_metadata'))
FALSE_FIELDS = ('full_journal_schema_validated', 'actor_tasks_verified',
    'active_session_verified', 'restoration_verified', 'receive_admission',
    'device_mutations', 'radio_operations')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise OSError('short_write')


def target_source(inputs):
    # Fixed memory source loading: no old runtime graph or device file staging.
    lines = ['import hashlib,sys,types', 'modules=(']
    for tag, pin in (('client_history_readonly', DIAGNOSTIC),):
        lines.append('(' + repr(tag) + ',' + str(pin[1]) + ',' + repr(pin[2]) + ',(')
        raw = inputs[pin[0]]
        # The ADB shell PTY uses a canonical single-line input limit. Each
        # original bytes fragment is at most256B; repr stays ASCII and small.
        for offset in range(0, len(raw), 256):
            lines.append(' ' + repr(raw[offset:offset + 256]) + ',')
        lines.append(')),')
    lines.extend((')', 'for name,size,sha,chunks in modules:',
        ' raw=b"".join(chunks)',
        ' if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("source_pin")',
        ' module=types.ModuleType(name);sys.modules[name]=module',
        ' exec(compile(raw,"<fixed-client-history-readonly>","exec"),module.__dict__)',
        'value=sys.modules["client_history_readonly"].observe()',
        'print("RESULT="+repr(value))', 'print("MTA_REMOTE_OK")'))
    raw = ('\n'.join(lines) + '\n').encode('ascii')
    if len(raw) > 128 * 1024 or any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('program_budget')
    return raw


def observed_remote_exit(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    exits = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
    return int(exits[0]) if len(exits) == 1 else 'UNKNOWN'


def parse_result(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = text.splitlines()
    exits = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
    results = [line[7:] for line in lines if line.startswith('RESULT=')]
    if len(exits) != 1 or lines.count('MTA_REMOTE_OK') != 1 or len(results) != 1:
        raise ValueError('result_unknown')
    value = ast.literal_eval(results[0])
    if (type(value) is not dict or set(value) != FIELDS or
            type(value['reason']) is not str or value['reason'] not in
                ('not_started', 'observed', 'client_root_missing', 'history_changed', 'observation_unknown') or
            value['root_empty'] is not None and type(value['root_empty']) is not bool or
            any(type(value[key]) is not bool for key in ('root_stable', 'resources_closed') + FALSE_FIELDS) or
            any(value[key] is not False for key in FALSE_FIELDS) or
            type(value['pending']) is not str or value['pending'] not in
                ('unknown', 'absent_snapshot', 'present', 'symlink') or
            type(value['entry_count']) is not int or not 0 <= value['entry_count'] <= 64 or
            type(value['counts']) is not dict or set(value['counts']) != set(CLASSES) or
            any(type(count) is not int or not 0 <= count <= 64 for count in value['counts'].values()) or
            sum(value['counts'].values()) != value['entry_count'] or
            type(value['private_entries']) is not list or len(value['private_entries']) != value['entry_count']):
        raise ValueError('result_fields')
    return int(exits[0]), value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-device', action='store_true')
    args = parser.parse_args()
    mode = 'readonly' if args.read_device else 'source'
    out = BASE / 'results' / ('client-history-readonly-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, value = {}, None
    report = dict(schema='p011-client-history-readonly-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False, device_mutations=False,
        radio_operations=False, owner_loaded=False, locks_taken=False, old_tests_replayed=0,
        history_changed_by_program=False, admission_modified=False,
        full_journal_schema_validated=False, actor_tasks_verified=False,
        active_session_verified=False, restoration_verified=False, receive_admission=False,
        host_error=None, host_exit='NOT_RUN', remote_exit='NOT_RUN', remote_status_known=False,
        source_scope='syntax_and_fixed_readonly_envelope', observation_seconds=10,
        remote_alarm_seconds=15, host_timeout_seconds=30)
    try:
        for path, size, sha in (DIAGNOSTIC, TRANSPORT):
            raw = (BASE / path).read_bytes()
            if len(raw) != size or digest(raw) != sha: raise ValueError('source_pin')
            inputs[path] = raw
        for path in (SELF, CMD): inputs[path] = (BASE / path).read_bytes()
        for path, raw in inputs.items():
            saved = out / 'private-inputs' / path
            saved.parent.mkdir(parents=True, exist_ok=True); write_new(saved, raw)
            if path.endswith('.py'): ast.parse(raw.decode('utf-8'), feature_version=(3, 5) if path == DIAGNOSTIC[0] else None)
        inventory = {path: dict(bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()}
        write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        source = target_source(inputs)
        ast.parse(source.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-target.py', source)
        report.update(source_checked=True, source_count=len(inputs), target_bytes=len(source), target_sha256=digest(source))
        if args.read_device:
            transport = types.ModuleType('fixed_client_history_transport'); transport.__file__ = str(BASE / TRANSPORT[0])
            exec(compile(inputs[TRANSPORT[0]], str(BASE / TRANSPORT[0]), 'exec'), transport.__dict__)
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(15);'
                'exec(sys.stdin.buffer.read(' + str(len(source)) + '))" p011-client-history-readonly-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run('history', ['shell', command], timeout=30, input_data=source)
            # Actual remote exit is independent of result/marker completeness.
            report['remote_exit'] = observed_remote_exit(raw)
            report['remote_status_known'] = type(report['remote_exit']) is int
            remote, value = parse_result(raw); report['remote_exit'] = remote
            for key in ('reason', 'root_empty', 'root_stable', 'pending', 'entry_count', 'resources_closed'):
                report[key] = value[key]
            for key, count in value['counts'].items(): report['count_' + key] = count
    except Exception as error:
        report['host_error'] = type(error).__name__
    finally:
        for tag in ('stdout', 'stderr'):
            path = private / ('01-history.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes(); report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout' and report['device_invoked']:
                    report['remote_exit'] = observed_remote_exit(raw)
                    report['remote_status_known'] = type(report['remote_exit']) is int
        path = private / '01-history.host-exit'
        if path.exists():
            text = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(text) if re.fullmatch(r'-?\d+', text) else 'TIMEOUT'
        write_new(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        report['source_preserved'] = bool(inputs) and all((BASE / path).read_bytes() == raw and
            (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items())
    source_ok = report['source_checked'] and report['source_preserved'] and report['host_error'] is None
    report['passed'] = source_ok and (not args.read_device or report['host_exit'] == 0 and
        report['remote_exit'] == 0 and report.get('stderr_bytes') == 0 and value is not None and
        value['reason'] in ('observed', 'client_root_missing') and value['resources_closed'])
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Readonly CLIENT metadata sampler. SOURCE is syntax/pin/envelope only. '
        b'Explicit --read-device enumerates at most64 root entries,8 directories,64 children/directory, '
        b'with one10s original observation deadline. No journal contents or /proc actor data read. '
        b'Fixed filename categories and stat metadata describe directory shape only; '
        b'active sessions, actor absence and restoration are not verified. '
        b'Unknown or unsupported entries remain unknown, never active or disposable by inference. '
        b'No records are written, removed, archived, locked or used to bypass the existing barrier. '
        b'Public ZIP contains only scalar result and this README. Names, full metadata, '
        b'paths and raw streams stay in private local evidence. No Owner/Boot/service or RF.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out), result_zip=str(bundle_path),
        zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
