"""Only one NEW Linux HOST timer/input method; no old generator, test or device."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_stage_bootstrap_timer_host_check.py'
TEST = 'tests/test_formal_send_stage_bootstrap_timer.py'
CMD = 'HOST_MTA_FORMAL_SEND_STAGE_BOOTSTRAP_TIMER_CHECK.cmd'
PASSED = 'results/formal-send-stage-bootstrap-source-20261004-192915-8da878a7'
ORIGINAL = 'results/formal-send-stage-source-20261004-182447-21000000'
PROFILES = (
    ('sender', 75607, 'f697cb833932455692d28f68401e0228fcdba289d6940c810c3bb8ca61b80f4d',
     1218562, '7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0'),
    ('observer', 75609, '171e5b002684f9ffb0226caf12f1ff783f1632e9fdca2612bdd1f75c3523feca',
     475365, '569af62782d444ff2be330000d7f0f85ce1c5b30698e767ba6bef3d7797aabb7'),
    ('ordinary', 75609, '6d4e6b0d40074101fe2ed4ffe01a04797fdf3019fa097d33b583bebe6f63a7f1',
     468929, '1a92780f8673a8dd52cc51a240e882a3208559eee518ea628e7f38235c53aaec'),
)
FIXED = (
    (TEST, 12152, '762a0283a579def26fc5612c1fa938e48e9b40e9a2e2fe04eef8d0d92f64056e'),
    ('candidate/formal-send-stage-v1/runtime/formal_send_stage.py',
     37382, 'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806'),
    ('candidate/formal-send-stage-bootstrap-v1/runtime/programs.py',
     69849, 'f2c1e165a4e4394365d30ffac9d7fc28d3ab03f4573cbbfba5ec98424ebf93c1'),
    ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py',
     13207, 'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d'),
    (PASSED + '/result.json', 2354, '39c7a51bf7e777bb187b45dfcb7665dc6456a07fa39115be02dcd0980a222b53'),
    (PASSED + '/SOURCE_RESULTS.zip', 1652, '30e326f8648727d6c23d3f1974ae24f84a5d54ce1087f1030d5cd3ddba98350d'),
)
ENVIRONMENT = dict(platform='linux', machine='x86_64', python=[3, 13], euid=0, egid=0)
CHILD_FIELDS = frozenset(('profile', 'child_exit', 'timeout', 'containment_kill_called',
    'resource_closure_known', 'resource_pending', 'stdout_bytes', 'stdout_sha256',
    'stderr_bytes', 'stderr_sha256', 'input_bytes', 'input_sha256', 'actual_timer_clear', 'framed_end_verified'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short_write')
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('snapshot_readback')


def fixed_source(name, size=None, sha=None):
    if type(name) is not str or name.startswith(('/', '\\')) or '..' in name.split('/'):
        raise ValueError('fixed_path')
    path = BASE / name
    for component in (path,) + tuple(path.parents):
        observed = component.lstat()
        if stat.S_ISLNK(observed.st_mode) or getattr(observed, 'st_file_attributes', 0) & 0x400:
            raise ValueError('source_link')
        if component == BASE:
            break
    before = path.stat()
    limit = 4 * 1024 * 1024 if size is None else size
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        ended = os.fstat(stream.fileno())
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    rows = [tuple(getattr(item, field) for field in fields) for item in (before, opened, ended, after)]
    # Windows Path.stat marks .cmd executable and reports creation ctime;
    # fstat reports different permission bits and modification ctime.
    # Each interface must still remain unchanged across the actual read.
    cross_same = (rows[0][:2] == rows[1][:2] and
                  stat.S_IFMT(rows[0][2]) == stat.S_IFMT(rows[1][2]) and
                  rows[0][3:8] == rows[1][3:8]) if os.name == 'nt' else rows[0] == rows[1]
    if (rows[0] != rows[3] or rows[1] != rows[2] or
            not cross_same or
            not stat.S_ISREG(before.st_mode) or len(raw) > limit or
            len(raw) != before.st_size or size is not None and len(raw) != size or
            sha is not None and digest(raw) != sha):
        raise ValueError('source_pin')
    return raw


def linux_path(path):
    value = path.absolute().as_posix()
    if not value.startswith('D:/project/P011/working/MtaP011-v0.1/results/'):
        raise ValueError('fixed_wsl_path')
    return '/mnt/d/' + value[3:]


def unique_json(derived, name):
    prefix = name.encode('ascii') + b'='
    values = [line[len(prefix):] for line in derived.splitlines() if line.startswith(prefix)]
    if len(values) != 1:
        raise ValueError('marker')
    return json.loads(values[0])


def verified_children(out, facts):
    if type(facts) is not list or len(facts) != 3:
        raise ValueError('child_count')
    private = out / 'private-child-raw'
    if {item.name for item in private.iterdir()} != {
            row[0] + suffix for row in PROFILES for suffix in
            ('.argv.json', '.stdout.raw', '.stderr.raw', '.exit.raw', '.initial-facts.json', '.verified-facts.json')}:
        raise ValueError('raw_inventory')
    for row, item in zip(PROFILES, facts):
        profile, program_size, program_sha, wire_size, wire_sha = row
        if (type(item) is not dict or set(item) != CHILD_FIELDS or item['profile'] != profile or
                type(item['child_exit']) is not int or item['child_exit'] != 1 or
                item['timeout'] is not False or item['containment_kill_called'] is not False or
                item['resource_closure_known'] is not True or item['resource_pending'] is not False or
                item['actual_timer_clear'] is not True or item['framed_end_verified'] is not True or
                item['input_bytes'] != wire_size or item['input_sha256'] != wire_sha):
            raise ValueError('child_contract')
        stdout = (private / (profile + '.stdout.raw')).read_bytes()
        stderr = (private / (profile + '.stderr.raw')).read_bytes()
        if (len(stdout) != item['stdout_bytes'] or digest(stdout) != item['stdout_sha256'] or
                len(stderr) != item['stderr_bytes'] or digest(stderr) != item['stderr_sha256'] or stderr or
                (private / (profile + '.exit.raw')).read_bytes() != b'1\n' or
                json.loads((private / (profile + '.verified-facts.json')).read_bytes()) != item):
            raise ValueError('child_raw_readback')
        initial = json.loads((private / (profile + '.initial-facts.json')).read_bytes())
        if (initial['profile'] != profile or initial['child_exit'] != 1 or initial['timeout'] is not False or
                initial['containment_kill_called'] is not False or initial['resource_closure_known'] is not False or
                initial['resource_pending'] is not True):
            raise ValueError('initial_observation')
        argv = json.loads((private / (profile + '.argv.json')).read_bytes())
        if (type(argv) is not list or len(argv) != 6 or argv[1:3] != ['-I', '-B'] or
                argv[3] != linux_path(out / 'private-inputs' / TEST) or
                argv[4:] != ['--fixed-bootstrap-child', profile]):
            raise ValueError('child_argv')
    return True


def finite_error(error):
    return {ValueError: 'host_value', OSError: 'host_io', KeyError: 'host_key',
            TypeError: 'host_type', json.JSONDecodeError: 'host_json'}.get(type(error), 'host_unknown')


def main():
    if sys.argv[1:]:
        return 2
    out = BASE / 'results' / ('formal-send-stage-bootstrap-timer-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources, stdout, stderr = {}, b'', b''
    report = dict(kind='formal-send-stage-bootstrap-timer-host-v1', passed=False,
        host_exit=None, method_exit=None, checker_exit=None, device_exit=None,
        new_methods=1, executed_methods=0, old_methods=0, contracts=0, case_count=0,
        exact_case_sequence=False, source_count=0, source_preserved=False, old_source_rerun=False,
        original_programs_used=False, original_wires_used=False, child_raw_readbacks=False,
        actual_timer_tested=False, actual_stdin_tested=False, actual_platform_refusal=False,
        actual_arm_stage_success=False, stage_complete=False, production_admitted=False,
        outer_seconds=180, inner_seconds=120, child_timeout_seconds=30, containment_not_closure=True,
        platform_model=False, clock_model=False, signal_model=False, os_model=False,
        physical_stdin_eof_verified=False, file_writes=None, stage_fds=None,
        boot=False, owner=False, helper=False, rf=False, device=False, phone=False,
        send_verified=False, receive_verified=False, restoration_verified=False,
        linux_environment=None, children=[], error_code=None)
    try:
        for name, size, sha in FIXED:
            sources[name] = fixed_source(name, size, sha)
        for profile, size, sha, wire_size, wire_sha in PROFILES:
            program = PASSED + '/' + profile + '.bootstrap.py'
            wire = PASSED + '/' + profile + '.wire.raw'
            original_wire = ORIGINAL + '/' + profile + '.wire.raw'
            sources[program] = fixed_source(program, size, sha)
            sources[wire] = fixed_source(wire, wire_size, wire_sha)
            sources[original_wire] = fixed_source(original_wire, wire_size, wire_sha)
            if sources[wire] != sources[original_wire]:
                raise ValueError('wire_bytes')
        proof = json.loads(sources[PASSED + '/result.json'])
        if not (proof['passed'] is True and proof['source_preserved'] is True and
                proof['actual_timer_tested'] is False and proof['source_inputs'] == 101 and
                proof['original_source_inputs'] == 90 and proof['original_programs_reused'] is True and
                proof['original_wires_reused'] is True and proof['target_program_executed'] is False):
            raise ValueError('original_source_proof')
        for name in (SELF, CMD):
            sources[name] = fixed_source(name)
        if len(sources) != 17:
            raise ValueError('input_count')
        inventory = {}
        for name, raw in sources.items():
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        argv = ['wsl.exe', '-d', 'kali-linux', '-u', 'root', '--exec', 'python3', '-I', '-B',
                linux_path(out / 'private-inputs' / TEST)]
        save(out / 'private-launch.json', (json.dumps(argv) + '\n').encode('ascii'))
        try:
            child = subprocess.run(argv, cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
            stdout, stderr, report['host_exit'] = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error_code'] = 'wsl_timeout_unknown'
        derived = stdout.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
        method = re.findall(rb'^BOOTSTRAP_TIMER_METHOD_EXIT=([01])$', derived, re.M)
        counts = re.findall(rb'^BOOTSTRAP_TIMER_CONTRACTS=([0-9]+)$', derived, re.M)
        cases = re.findall(rb'^BOOTSTRAP_TIMER_HOST_CASE=(sender|observer|ordinary)$', derived, re.M)
        report['method_exit'] = int(method[0]) if len(method) == 1 else None
        report['contracts'] = int(counts[0]) if len(counts) == 1 else 0
        report['case_count'] = len(cases)
        report['exact_case_sequence'] = tuple(item.decode('ascii') for item in cases) == ('sender', 'observer', 'ordinary')
        report['linux_environment'] = unique_json(derived, 'BOOTSTRAP_TIMER_HOST_ENV')
        child_facts = unique_json(derived, 'BOOTSTRAP_TIMER_CHILD_FACTS')
        report['child_raw_readbacks'] = verified_children(out, child_facts)
        report['children'] = child_facts
        report['original_programs_used'] = report['original_wires_used'] = True
    except Exception as error:
        if report['error_code'] is None:
            report['error_code'] = finite_error(error)
        save(out / 'private-error-kind.txt', (type(error).__name__ + '\n').encode('ascii'))
    for name, raw in (('stdout', stdout), ('stderr', stderr)):
        save(out / (name + '.raw'), raw)
        report[name + '_bytes'], report[name + '_sha256'] = len(raw), digest(raw)
    save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    save(out / 'method-exit.raw', (str(report['method_exit']) + '\n').encode('ascii'))
    save(out / 'device-exit.raw', b'NOT_RUN_DEVICE\n')
    report['source_count'] = len(sources)
    try:
        report['source_preserved'] = len(sources) == 17 and all(
            fixed_source(name, len(raw), digest(raw)) == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
    except Exception as error:
        if report['error_code'] is None:
            report['error_code'] = finite_error(error)
    derived_err = stderr.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
    report['passed'] = (report['host_exit'] == 0 and report['method_exit'] == 0 and
        report['error_code'] is None and report['source_preserved'] and report['child_raw_readbacks'] and
        report['contracts'] == 3 and report['case_count'] == 3 and report['exact_case_sequence'] and
        report['linux_environment'] == ENVIRONMENT and
        len(re.findall(rb'^Ran 1 test in [0-9.]+s$', derived_err, re.M)) == 1 and
        len(re.findall(rb'^OK$', derived_err, re.M)) == 1)
    if report['passed']:
        report['executed_methods'] = 1
        report['actual_timer_tested'] = report['actual_stdin_tested'] = report['actual_platform_refusal'] = True
        report['file_writes'] = report['stage_fds'] = 0
    report['checker_exit'] = 0 if report['passed'] else 1
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One NEW HOST method / three actual Linux x86_64 Python3.13 root children. '
        b'Each uses a fixed previously generated bootstrap program and byteexact original wire through real stdin, '
        b'real SIGALRM/ITIMER_REAL and monotonic/thread identity. No flags/platform/clock/os/signal model. '
        b'All three tested child exits remain original SystemExit(1), with actual StageError/platform refusal; '
        b'test method and WSL runner exit0 only if the exact contracts pass. Original retained stage has zero '
        b'file writes, directories and FD inventory; real framed end is verified but physical stdin EOF is NOT. '
        b'Original inner120 and single outer180 are unchanged; real timer is independently clear at child end. '
        b'Unexpected 30s child timeout is HOST containment only and never grants resource closure; WSL 90s '
        b'timeout remains unknown. This is NOT ARM stage success, graph startup, Boot, Owner, helper, RF, '
        b'device, phone, send, receive, restore or admission. No old test, checker, generator or SOURCE is rerun. '
        b'17 fixed inputs and private snapshots, child stdin bytes, argv/raw stdout/raw stderr, each original '
        b'child exit, WSL/test/checker exits and errors stay local. Public ZIP contains only result.json and '
        b'README.txt; no raw input, source, credentials, process identifier or device path.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', note)
    save(out / 'checker-exit.raw', (str(report['checker_exit']) + '\n').encode('ascii'))
    bundle = out / 'HOST_RESULTS.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return report['checker_exit']


if __name__ == '__main__':
    raise SystemExit(main())
