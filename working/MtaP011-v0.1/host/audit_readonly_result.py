"""PC-only audit of a fixed successful readonly47/51 artifact, never a test rerun.

Reads source/payload/raw/result/ZIP bytes only. Does not import target modules,
execute a payload, run ADB, write files, grant RF/restore or claim phone access.
Optional reference compares full Snapshot.key data, not collector session PID.
"""
import argparse
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SPECS = {
    'client-readonly-diagnostic-v47': (
        '47', 'host/client_readonly_diagnostic_v47_p011.py',
        'c983c6c466359986e1a322cd4a775bbb9b91bcb0379825d8c0bb7a005199d03d',
        'host/client_readonly_diagnostic_v47_source_manifest.json',
        '212caa6f86340d6fcfedee5714d8df5226e1eaf1e151b16c0742ab900c4ffbe0',
        'candidate/client-readonly-diagnostic-v47/runtime/mta_client_readonly_baseline.py',
        '8155964210dd374c35fefcd92867ffe970488e0d826a4e47297536b277c01c99'),
    'client-readonly-proc-vanish-v51': (
        '51', 'host/client_readonly_proc_vanish_v51_p011.py',
        '318f2ea6fdbf32ac9f302ed952d7e7aee5dbb9071a174618e2d70cea5c095574',
        'host/client_readonly_proc_vanish_v51_source_manifest.json',
        '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60',
        'candidate/client-readonly-proc-vanish-v51/runtime/mta_client_readonly_baseline.py',
        'c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad'),
}


def require(value):
    if not value:
        raise ValueError('artifact_audit_failed')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def result_path(value):
    path = (BASE / value).resolve()
    require(path.is_relative_to((BASE / 'results').resolve()) and path.is_dir())
    return path


def source_payload(out, report, spec):
    number, driver_path, driver_sha, map_path, map_sha, leaf_path, leaf_sha = spec
    require(digest((BASE / driver_path).read_bytes()) == driver_sha == report['driver_sha256'])
    raw_map = (BASE / map_path).read_bytes()
    require(digest(raw_map) == map_sha == report['source_manifest_sha256'])
    plan = json.loads(raw_map)
    require(len(plan['sources']) == 35 and len({r['module'] for r in plan['sources']}) == 35)
    payload = (out / 'private-raw/payload.py').read_bytes()
    tree = ast.parse(payload.decode('utf-8'), feature_version=(3, 5))
    wanted = {'SOURCES', 'LEAF_DATA', 'LEAF_PIN', 'RUN_TOKEN', 'SOURCE_MAP'}
    values = {target.id: ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign) for target in node.targets
              if isinstance(target, ast.Name) and target.id in wanted}
    require(set(values) == wanted and len(values['SOURCES']) == 35 and values['SOURCE_MAP'] == map_sha)
    for (name, pin, encoded), row in zip(values['SOURCES'], plan['sources']):
        raw = (BASE / row['path']).read_bytes()
        require(name == row['module'] and pin == row['sha256'] == digest(raw))
        require(len(raw) == row['bytes'] and base64.b64decode(encoded, validate=True) == raw)
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    leaf = (BASE / leaf_path).read_bytes()
    require(values['LEAF_PIN'] == leaf_sha == report['leaf_sha256'] == digest(leaf))
    require(base64.b64decode(values['LEAF_DATA'], validate=True) == leaf)
    ast.parse(leaf.decode('utf-8'), feature_version=(3, 5))
    return number, payload


def decode(out, number, payload):
    private = out / 'private-raw'
    stem = '02-native-readonly'
    require((private / (stem + '.host-exit')).read_bytes() == b'0')
    require((private / (stem + '.remote-exit')).read_bytes() == b'0')
    require(not (private / (stem + '.stderr.raw')).read_bytes())
    raw = (private / (stem + '.stdout.raw')).read_bytes()
    # Derived view only; raw files remain byte-for-byte unchanged.
    text = raw.decode('utf-8').replace('\r\r\n', '\n').replace('\r\n', '\n')
    echo = payload.decode('utf-8').replace('\r\r\n', '\n').replace('\r\n', '\n')
    if text.startswith(echo):
        text = text[len(echo):]
    lines = text.splitlines()
    prefix = 'P011_V' + number
    require(lines.count(prefix + '_STARTED') == lines.count(prefix + '_DONE') == 1)
    require([line for line in lines if line.startswith(prefix + '_EXIT=')] == [prefix + '_EXIT=0'])
    public = [line[len(prefix + '_PUBLIC='):] for line in lines if line.startswith(prefix + '_PUBLIC=')]
    native = [line[len(prefix + '_PRIVATE='):] for line in lines if line.startswith(prefix + '_PRIVATE=')]
    require(len(public) == len(native) == 1)
    return json.loads(public[0]), json.loads(native[0])


def inventories(native):
    count = missing = datagrams = 0
    for row in native['collectors']:
        require(not row['unknown'] and row['returned'])
        status = row['status']
        require(status['closed'] and not status['resource_pending'] and status['round_count'] == 2)
        require(row['caught_original_v47'] is None)
        require(status['resource_count'] == status['closed_count'] == len(row['tickets']))
        datagrams += status['datagram_count']
        for ticket in row['tickets']:
            require(ticket['closed'] is True and ticket['unknown'] is False and ticket['pipe_refs_valid'] is True)
            error = ticket['open_error_original_v47']
            if error is not None:
                require(error['type'] == 'FileNotFoundError' and type(error['errno']) is int and error['errno'] == 2)
                require(error['filename'] == ticket['open_requested_path_v47'])
                require(ticket['fd'] is None and ticket['attempted'] is False)
                missing += 1
            count += 1
    proc = native['proc']
    require(proc['history_closed'] and not proc['pending'] and not proc['active'] and not proc['history_active'])
    for generation in proc['history']:
        require(generation['ended'] and not generation['active'] and not generation['unknown'] and not generation['late'])
        for ticket in generation['tickets']:
            require(ticket['open_called'] and ticket['returned'] and ticket['registered'])
            require(ticket['close_attempted'] and ticket['close_returned'] and ticket['close_result'] is None)
            require(ticket['ebadf_observed'] and ticket['ebadf_errno'] == 9 and not ticket['unknown'])
    return count, len(proc['history']), missing, datagrams


def snapshot_key(value):
    result = copy.deepcopy(value)
    for actor in result['stock_actors']:
        require(all(task[2] in ('R', 'S', 'D', 'T', 't', 'I') for task in actor['tasks']))
        # Actual Actor.key retains complete PID/start/task identity, not live state.
        actor['tasks'] = [task[:2] for task in actor['tasks']]
    result['stock_actors'].sort(key=lambda actor: actor['pid'])
    for key in ('stock_hashes', 'interfaces', 'ipv6_addresses', 'ipv6_routes'):
        result[key].sort(key=lambda row: json.dumps(row, sort_keys=True))
    for key in ('addresses', 'routes', 'rules'):
        result['ipv4'][key].sort(key=lambda row: json.dumps(row, sort_keys=True))
    return result


def zip_audit(out):
    names = ['result.json', 'source-pins.json', 'README.txt', 'SHA256SUMS.txt']
    path = out / 'public-result.zip'
    with zipfile.ZipFile(path) as bundle:
        require(bundle.namelist() == names and bundle.testzip() is None)
        for name in names:
            raw = bundle.read(name)
            info = bundle.getinfo(name)
            require(raw == (out / name).read_bytes() and len(raw) == info.file_size)
            require(info.CRC == zlib.crc32(raw) & 0xffffffff)
    require((out / names[-1]).read_text().splitlines() == [
        digest((out / name).read_bytes()) + '  ' + name for name in names[:-1]])
    return {'members': len(names), 'bytes': path.stat().st_size, 'sha256': digest(path.read_bytes())}


def audit(out):
    report = json.loads((out / 'result.json').read_bytes())
    require(report['schema'] in SPECS and report['read_success'] is True)
    require(report['host_exit'] == report['remote_exit'] == 0 and not report['host_timeout'])
    require(report['remote_closure_verified'] and report['full_native_rounds'] == 2 and not report['resource_pending'])
    number, payload = source_payload(out, report, SPECS[report['schema']])
    public, native = decode(out, number, payload)
    require(native['error'] is None and native['owner_error_original'] is None)
    status = native['owner_status']
    require(public == status and status['read_success'] and status['full_native_rounds'] == 2)
    require(status['pending_absence_before'] and status['pending_absence_after'] and not status['resource_pending'])
    for key in ('staging_attempted', 'rf_requested', 'restoration_verified', 'source_factory_ready',
                'send_available', 'receive_available', 'phone_tested'):
        require(report[key] is False and status[key] is False)
    require(native['platform_before'] == native['platform_after'])
    count, generations, missing, datagrams = inventories(native)
    return native, {'source_count': 35, 'payload_bytes': len(payload), 'collector_closed': count,
                    'proc_generations_closed': generations, 'known_unopened_comm_receipts': missing,
                    'datagrams': datagrams, 'zip': zip_audit(out)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result')
    parser.add_argument('--reference')
    args = parser.parse_args()
    current, result = audit(result_path(args.result))
    if args.reference:
        previous, unused = audit(result_path(args.reference))
        require(snapshot_key(current['snapshot']) == snapshot_key(previous['snapshot']))
        require(current['platform_before'][:3] == previous['platform_before'][:3])
        result.update(full_stock_network_reference_equal=True, cross_session_os_python_euid_equal=True,
                      collector_session_pid_not_conflated=True)
    result.update(audit='PASS', device_invoked=False, files_written=False, overall_transfer_verified=False)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
