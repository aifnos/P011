"""Independent bounded CLIENT-history observation. Default PC SOURCE only.

Explicit --read-device performs only fixed-root reads through identified P011
ADB. It never loads service/Owner/Boot, takes locks, repairs, archives or grants
admission. Private snapshots/raw streams may contain metadata paths/source hashes/tokens.
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
DIAGNOSTIC = ('candidate/client-source-metadata-readonly-v1/runtime/client_source_metadata.py', 8482,
    '2fb258be5cedf420e98504171915f9694327f4e97a177772ba686d1f8f9d16d1')
JSON_SOURCE = ('runtime/p011_json.py', 8061,
    'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
SELF = 'host/device_client_source_metadata_readonly_v1_check.py'
CMD = 'CHECK_MTA_CLIENT_SOURCE_METADATA_READONLY_V1.cmd'
FIELDS = frozenset(('reason', 'roots_stable', 'metadata_file_count', 'decoded_count',
    'ctrl_socket_count', 'ctrl_entry_count', 'resources_closed', 'summaries',
    'private_files', 'private_ctrl', 'active_session_verified', 'restoration_verified',
    'receive_admission', 'device_mutations', 'radio_operations', 'full_schema_validated'))
FALSE_FIELDS = ('active_session_verified', 'restoration_verified', 'receive_admission',
                'device_mutations', 'radio_operations', 'full_schema_validated')
TAGS = ('candidate_1', 'deployment_1', 'candidate_2', 'static_source_2')
STATUS_KEYS = frozenset(('ready', 'not_ready', 'complete', 'source_only', 'static_only',
                        'runtime_ready', 'rf_ready', 'rf_started', 'receive_ready'))


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise OSError('short_write')


def target_source(inputs):
    # Fixed memory source loading: no old runtime graph or device file staging.
    lines = ['import hashlib,sys,types', 'modules=(']
    for tag, pin in (('p011_json', JSON_SOURCE), ('client_source_metadata_readonly', DIAGNOSTIC)):
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
        'value=sys.modules["client_source_metadata_readonly"].observe()',
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
                ('not_started', 'observed', 'metadata_changed', 'observation_unknown') or
            any(type(value[key]) is not bool for key in ('roots_stable', 'resources_closed') + FALSE_FIELDS) or
            any(value[key] is not False for key in FALSE_FIELDS) or
            any(type(value[key]) is not int or not 0 <= value[key] <= maximum
                for key, maximum in (('metadata_file_count', 4), ('decoded_count', 4),
                                     ('ctrl_socket_count', 32), ('ctrl_entry_count', 32))) or
            type(value['summaries']) is not list or len(value['summaries']) != value['decoded_count'] or
            type(value['private_files']) is not list or len(value['private_files']) != value['metadata_file_count'] or
            type(value['private_ctrl']) is not list or len(value['private_ctrl']) > 2):
        raise ValueError('result_fields')
    for index, item in enumerate(value['summaries']):
        if (type(item) is not dict or set(item) != {'tag', 'schema', 'kind', 'keys',
                'withheld_key_count', 'version', 'declared_status', 'full_schema_validated', 'readiness_verified'} or
                item['tag'] != TAGS[index] or type(item['keys']) is not list or len(item['keys']) > 64 or
                any(type(key) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,63}', key) is None for key in item['keys']) or
                type(item['withheld_key_count']) is not int or not 0 <= item['withheld_key_count'] <= 64 or
                item['version'] is not None and (type(item['version']) is not int or not 0 <= item['version'] <= 1000) or
                any(item[key] is not None and (type(item[key]) is not str or
                    re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,95}', item[key]) is None) for key in ('schema', 'kind')) or
                type(item['declared_status']) is not dict or not set(item['declared_status']) <= STATUS_KEYS or
                any(type(flag) is not bool for flag in item['declared_status'].values()) or
                item['full_schema_validated'] is not False or item['readiness_verified'] is not False):
            raise ValueError('summary_fields')
    return int(exits[0]), value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-device', action='store_true')
    args = parser.parse_args()
    mode = 'readonly' if args.read_device else 'source'
    out = BASE / 'results' / ('client-source-metadata-readonly-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, value = {}, None
    report = dict(schema='p011-client-source-metadata-readonly-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False, device_mutations=False,
        radio_operations=False, owner_loaded=False, locks_taken=False, old_tests_replayed=0,
        history_changed_by_program=False, admission_modified=False,
        full_schema_validated=False, metadata_contents_read=False,
        active_session_verified=False, restoration_verified=False, receive_admission=False,
        host_error=None, host_exit='NOT_RUN', remote_exit='NOT_RUN', remote_status_known=False,
        source_scope='syntax_and_fixed_readonly_envelope', observation_seconds=10,
        remote_alarm_seconds=15, host_timeout_seconds=30)
    try:
        for path, size, sha in (DIAGNOSTIC, JSON_SOURCE, TRANSPORT):
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
                'exec(sys.stdin.buffer.read(' + str(len(source)) + '))" p011-client-source-metadata-readonly-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run('history', ['shell', command], timeout=30, input_data=source)
            # Actual remote exit is independent of result/marker completeness.
            report['remote_exit'] = observed_remote_exit(raw)
            report['remote_status_known'] = type(report['remote_exit']) is int
            remote, value = parse_result(raw); report['remote_exit'] = remote
            for key in ('reason', 'roots_stable', 'metadata_file_count', 'decoded_count',
                        'ctrl_socket_count', 'ctrl_entry_count', 'resources_closed'):
                report[key] = value[key]
            report['metadata_contents_read'] = value['metadata_file_count'] > 0
            report['metadata_summaries'] = value['summaries']
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
        value['reason'] == 'observed' and value['roots_stable'] and value['resources_closed'] and
        value['metadata_file_count'] == 4 and value['decoded_count'] == 4)
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Readonly four metadata JSON files in two previously observed CLIENT directories. '
        b'Only fixed candidate.json x2, deployment.json and static-source.json are opened, '
        b'at most8192 bytes each, nofollow/exact-size/full-stat readback. ctrl directories are '
        b'bounded to16 names each and statted for socket type only; no connect or recv. '
        b'Original10s observation/remote15s/host30s unchanged. JSON data uses bundled p011_json. '
        b'Public summaries expose schema/kind/safe keys/boolean declarations only; full raw '
        b'JSON, token/path/source hashes and filenames remain private. Declarations are not '
        b'full-schema, runtime-readiness, actor-absence, recovery or admission proofs. '
        b'No journals, source code execution, user files, locks, writes, removal, archive or RF. '
        b'No old metadata sampler/test is replayed. SOURCE is syntax/pins/envelope only.\\n')

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
