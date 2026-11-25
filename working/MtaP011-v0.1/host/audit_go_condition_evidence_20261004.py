"""Read-only audit of two saved device observations. No device or test execution."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import zipfile

BASE = Path(__file__).resolve().parents[1]
STATE = BASE/'results/device-state-readonly-20261004-152217-9e559fdb'
GO = BASE/'results/go-pending-readonly-20261004-152225-8188956e'


def require(value, code):
    if value is not True: raise ValueError(code)


def parsed(root, stem):
    raw = (root/'private-raw'/(stem+'.stdout.raw')).read_bytes()
    require((root/'private-raw'/(stem+'.host-exit')).read_bytes() == b'0', 'original_host_exit')
    require((root/'private-raw'/(stem+'.stderr.raw')).read_bytes() == b'', 'original_stderr')
    derived = raw.decode('utf-8').replace('\r\r\n','\n').replace('\r\n','\n')
    lines = derived.splitlines()
    require(lines.count('MTA_REMOTE_OK') == 1 and lines.count('MTA_REMOTE_EXIT=0') == 1,
            'original_remote_markers')
    result = [line[7:] for line in lines if line.startswith('RESULT=')]
    require(len(result) == 1, 'original_result_count')
    return ast.literal_eval(result[0])


def zip_audit(root):
    path = root/'public-result.zip'
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist() == ['result.json','README.txt'] and archive.testzip() is None,
                'zip_inventory_crc')
        require(archive.read('result.json') == (root/'result.json').read_bytes(), 'zip_result_bytes')
        if (root/'README.txt').exists():
            require(archive.read('README.txt') == (root/'README.txt').read_bytes(), 'zip_readme_bytes')
        else:
            require(archive.read('README.txt') == b'Two current read-only observations only. No candidate, RF, recovery or reboot. No pending ownership/schema or complete network-restoration assertion. Raw outputs remain private.\n', 'zip_fixed_readme')
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def unpack(value):
    if type(value) is list: return [unpack(item) for item in value]
    if type(value) is dict:
        if set(value) == {'bytes','bytes_b64'}:
            raw = base64.b64decode(value['bytes_b64'], validate=True)
            require(len(raw) == value['bytes'], 'private_byte_length')
            return raw
        return {key:unpack(item) for key,item in value.items()}
    return value


def normalize(value):
    if type(value) in (list,tuple): return [normalize(item) for item in value]
    if type(value) is dict: return {key:normalize(item) for key,item in value.items()}
    return value


def main():
    first = parsed(STATE,'01-current-state-first')
    second = parsed(STATE,'02-current-state-second')
    state = json.loads((STATE/'result.json').read_bytes())
    for field in ('same_boot','same_stock','same_interfaces','same_pending_bytes',
                  'same_ipv4_main_routes','same_ipv6_routes','stock_pins_match'):
        require(state[field] is True, 'original_state_projection')
    for field in ('boot','stock','interfaces','pending','ipv4_routes','ipv6_routes'):
        require(first[field] == second[field], 'original_state_equality')
    require((STATE/'source.py').read_bytes() == (BASE/'host/device_state_snapshot_20261002.py').read_bytes(),
            'state_source_current')
    actual = parsed(GO,'01-old-go-reservation-readonly')
    saved = unpack(json.loads((GO/'private-raw/remote-result.json').read_bytes()))
    require(normalize(actual) == saved, 'saved_remote_result_original')
    require(actual['before'] == actual['after'] and actual['complete'] is True and
            actual['local_fds_closed'] is True and not actual['close_errors'], 'go_original_complete')
    require(len(actual['rows']) == 16 and all(row['returned'] and row['closed'] and not row['unknown']
            for row in actual['rows']), 'go_actual_fds')
    require(len(actual['actor_passes']) == len(actual['network_passes']) == 2 and
            all(len(group) == 2 and all(row['all_paths_absent'] for row in group)
                for group in actual['actor_passes']), 'go_actual_actors')
    require(all(not row[key] for row in actual['network_passes']
                for key in ('project_netdevs','old_endpoint_paths','old_unix_live')), 'go_actual_endpoints')
    require((GO/'private-raw/host-source.py').read_bytes() ==
            (BASE/'host/device_go_pending_readonly_20261004.py').read_bytes(), 'go_source_current')
    pending, journal = actual['before']['pending_raw'],actual['before']['journal_raw']
    require(len(pending) == 340 and hashlib.sha256(pending).hexdigest() ==
            '80dae11a3a8b19e9c799058598b86ace18072e4ff8afe7128297adce9dd8a818', 'go_pending_pin')
    require(len(journal) == 7138 and hashlib.sha256(journal).hexdigest() ==
            '01c200261bae27578881dd3ef97e165e848a14b877b883405a017bc298d210c6', 'go_journal_pin')
    report = json.loads((GO/'result.json').read_bytes())
    require(report['diagnostic_complete'] is True and report['pending_retired'] is False and
            report['full_network_restore_verified'] is False and
            report['non_netdev_p2p_absence_verified'] is False, 'go_scope_projection')
    print(json.dumps(dict(audit_passed=True, original_host_and_remote_exit=0,
        state_zip=zip_audit(STATE), go_zip=zip_audit(GO), actual_go_original_fds=16,
        raw_private_results_equal=True, tests_replayed=False, device_access=False,
        pending_retired=False, non_netdev_p2p_proved=False, full_restore_proved=False), sort_keys=True))


if __name__ == '__main__': main()
