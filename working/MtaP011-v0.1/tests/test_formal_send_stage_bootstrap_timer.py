"""One new HOST method: real Linux timers and stdin, ARM platform is NOT modeled.

Each fixed child exits with its original SystemExit(1) after the actual stager
refuses x86/Python3.13. That expected refusal is not ARM staging success.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import unittest


BASE = Path(__file__).resolve().parents[1]
PASSED = 'results/formal-send-stage-bootstrap-source-20261004-192915-8da878a7'
PROFILES = (
    ('sender', 75607, 'f697cb833932455692d28f68401e0228fcdba289d6940c810c3bb8ca61b80f4d',
     1218562, '7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0'),
    ('observer', 75609, '171e5b002684f9ffb0226caf12f1ff783f1632e9fdca2612bdd1f75c3523feca',
     475365, '569af62782d444ff2be330000d7f0f85ce1c5b30698e767ba6bef3d7797aabb7'),
    ('ordinary', 75609, '6d4e6b0d40074101fe2ed4ffe01a04797fdf3019fa097d33b583bebe6f63a7f1',
     468929, '1a92780f8673a8dd52cc51a240e882a3208559eee518ea628e7f38235c53aaec'),
)
ENVIRONMENT = dict(platform='linux', machine='x86_64', python=[3, 13], euid=0, egid=0)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_file(name, size, sha):
    path = BASE / PASSED / name
    before = path.stat()
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(size + 1)
        ended = os.fstat(stream.fileno())
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    rows = [tuple(getattr(item, field) for field in fields) for item in (before, opened, ended, after)]
    if not (rows.count(rows[0]) == 4 and len(raw) == size and digest(raw) == sha):
        raise ValueError('fixed_input')
    return path, raw


def actual_environment():
    value = dict(platform=sys.platform, machine=os.uname()[4],
                 python=list(sys.version_info[:2]), euid=os.geteuid(), egid=os.getegid())
    if value != ENVIRONMENT or sys.flags.optimize or threading.current_thread() is not threading.main_thread():
        raise ValueError('actual_linux_environment')
    return value


def fixed_child(profile):
    """No clock, OS, flags, signal or platform projection; no optional source input."""
    environment = actual_environment()
    if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise ValueError('initial_timer')
    choices = [row for row in PROFILES if type(profile) is str and row[0] == profile]
    if len(choices) != 1:
        raise ValueError('fixed_profile')
    row = choices[0]
    path, raw = fixed_file(profile + '.bootstrap.py', row[1], row[2])
    namespace = dict(__name__='fixed_bootstrap_host_private', __file__=str(path))
    primary = None
    try:
        exec(compile(raw, '<fixed-bootstrap-host-program>', 'exec'), namespace)
    except BaseException as error:
        primary = error
    wrapper = namespace.get('_wrapper')
    ticket = None if wrapper is None else wrapper._RETAINED
    original = None if type(ticket) is not dict else ticket.get('namespace')
    stage = None if type(original) is not dict else original.get('_RETAINED')
    stage_module = None if type(original) is not dict else original.get('_module')
    stage_error = None if type(original) is not dict else original.get('_primary')
    original_result = None if type(original) is not dict else original.get('_result')
    valid = (type(primary) is SystemExit and primary.code == 1 and type(ticket) is dict and
        ticket['exec_error'] is primary and ticket['first_error'] is primary and
        original is ticket['namespace_original'] and type(original_result) is dict and
        stage_module is ticket['stage_module'] and stage is ticket['stage'] and
        type(stage_error) is stage_module.StageError and stage_error.code == 'platform' and
        type(stage) is stage_module.FixedStage and stage.first_error is stage_error and
        stage.called is True and stage.ended is True and stage.close_called is True and stage.closed is True and
        stage.rows is stage._rows_original and stage.rows == [] and
        stage.creations is stage._creations_original and stage.creations == [] and
        ticket['timer_called'] is True and ticket['timer_returned'] is True and
        ticket['timer_return'] == (0.0, 0.0) and ticket['timer_release_called'] is True and
        ticket['timer_released'] is True and ticket['timer_unknown'] is False and
        ticket['original_until'] == ticket['started'] + 180.0 and
        original['_until'] == original['_started'] + 120.0 and
        original['_until'] < ticket['original_until'] and
        signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
        signal.getsignal(signal.SIGALRM) == signal.SIG_DFL)
    observation = dict(environment=environment, profile=profile, original_exit=1 if valid else None,
        actual_timer_clear=signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        actual_default_handler=signal.getsignal(signal.SIGALRM) == signal.SIG_DFL,
        original_retained_contracts=bool(valid), actual_platform_refusal=bool(valid),
        outer_absolute_seconds=180, inner_absolute_seconds=120,
        actual_arm_stage_success=False, physical_stdin_eof_verified=False)
    print('BOOTSTRAP_TIMER_CHILD_OBSERVATION=' + json.dumps(observation, sort_keys=True), flush=True)
    if not valid:
        raise ValueError('original_child_contract')
    raise primary  # Keep the original tested child SystemExit(1), not a success exit.


def save_private(path, raw):
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('raw_short_write')
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('raw_readback')


def marker(raw, name, json_value=False):
    lines = raw.splitlines()
    values = [line[len(name) + 1:] for line in lines if line.startswith(name.encode('ascii') + b'=')]
    if len(values) != 1:
        raise ValueError('unique_marker')
    return json.loads(values[0]) if json_value else ast.literal_eval(values[0].decode('ascii'))


class FixedBootstrapTimerHostTest(unittest.TestCase):
    def test_three_actual_timers_and_fixed_stdin(self):
        environment = actual_environment()
        print('BOOTSTRAP_TIMER_HOST_ENV=' + json.dumps(environment, sort_keys=True), flush=True)
        private = BASE.parent / 'private-child-raw'
        private.mkdir(mode=0o700, exist_ok=False)
        observations = []
        for row in PROFILES:
            profile = row[0]
            _, wire = fixed_file(profile + '.wire.raw', row[3], row[4])
            fixed_file(profile + '.bootstrap.py', row[1], row[2])
            argv = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--fixed-bootstrap-child', profile]
            save_private(private / (profile + '.argv.json'), (json.dumps(argv) + '\n').encode('ascii'))
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr, failure, timed_out, terminated = b'', b'', None, False, False
            try:
                stdout, stderr = child.communicate(input=wire, timeout=30)
            except subprocess.TimeoutExpired as error:
                failure, timed_out = error, True
                stdout, stderr = error.stdout or b'', error.stderr or b''
                # Only contain this HOST child. Killing/reaping does NOT prove its inventory or timer closed.
                try:
                    child.kill()
                    terminated = True
                    stdout, stderr = child.communicate(timeout=5)
                except BaseException:
                    pass
            except BaseException as error:
                failure = error
                try:
                    child.kill()
                    terminated = True
                    stdout, stderr = child.communicate(timeout=5)
                except BaseException:
                    pass
            finally:
                save_private(private / (profile + '.stdout.raw'), stdout)
                save_private(private / (profile + '.stderr.raw'), stderr)
                save_private(private / (profile + '.exit.raw'), (str(child.returncode) + '\n').encode('ascii'))
                facts = dict(profile=profile, child_exit=child.returncode, timeout=timed_out,
                    containment_kill_called=terminated, resource_closure_known=False,
                    resource_pending=True,
                    stdout_bytes=len(stdout), stdout_sha256=digest(stdout),
                    stderr_bytes=len(stderr), stderr_sha256=digest(stderr))
                save_private(private / (profile + '.initial-facts.json'),
                             (json.dumps(facts, sort_keys=True) + '\n').encode('ascii'))
            if failure is not None:
                raise failure
            self.assertEqual(child.returncode, 1)
            self.assertEqual(stderr, b'')
            self.assertEqual(stdout.count(b'STAGE_ERROR=StageError\n'), 1)
            self.assertNotIn(b'STAGE_OK=', stdout)
            stage = marker(stdout, 'STAGE_RESULT')
            expected_stage = dict(kind='formal-send-stage-v1-files-only', profile=profile,
                stage_complete=False, resource_pending=False, staging_pending=False,
                original_fds=0, original_fds_closed=0, created_files=0, created_directories=0,
                existing_complete=False, prerequisites=0, service_parent_count=0,
                receive=False, send=False, boot=False, owner=False, helper=False, rf=False,
                restoration=False, phone=False, payload_framed_end_verified=True,
                physical_stdin_eof_verified=False, source_only_template=False)
            self.assertEqual(stage, expected_stage)
            expected_bootstrap = dict(profile=profile, program_verified=True, program_exec_called=True,
                program_returned=False, original_stage_complete=False, original_stage_resources_closed=True,
                resource_pending=False, outer_timer_installed=True, outer_timer_released=True,
                outer_timer_unknown=False, inner_seconds=120, outer_seconds=180,
                payload_framed_end_verified=True, physical_stdin_eof_verified=False, error_kind='SystemExit')
            self.assertEqual(marker(stdout, 'BOOTSTRAP_RESULT'), expected_bootstrap)
            observation = marker(stdout, 'BOOTSTRAP_TIMER_CHILD_OBSERVATION', True)
            self.assertEqual(observation, dict(environment=ENVIRONMENT, profile=profile, original_exit=1,
                actual_timer_clear=True, actual_default_handler=True, original_retained_contracts=True,
                actual_platform_refusal=True, outer_absolute_seconds=180, inner_absolute_seconds=120,
                actual_arm_stage_success=False, physical_stdin_eof_verified=False))
            facts.update(resource_closure_known=True, resource_pending=False, input_bytes=len(wire),
                         input_sha256=digest(wire), actual_timer_clear=True, framed_end_verified=True)
            save_private(private / (profile + '.verified-facts.json'),
                         (json.dumps(facts, sort_keys=True) + '\n').encode('ascii'))
            observations.append(facts)
            print('BOOTSTRAP_TIMER_HOST_CASE=' + profile, flush=True)
        print('BOOTSTRAP_TIMER_CHILD_FACTS=' + json.dumps(observations, sort_keys=True), flush=True)
        print('BOOTSTRAP_TIMER_CONTRACTS=3', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--fixed-bootstrap-child':
        fixed_child(sys.argv[2])
    elif len(sys.argv) == 1:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixedBootstrapTimerHostTest)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() else 1
        print('BOOTSTRAP_TIMER_METHOD_EXIT=' + str(code), flush=True)
        raise SystemExit(code)
    else:
        raise SystemExit(2)
