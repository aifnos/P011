# -*- coding: utf-8 -*-
"""HOST_ONLY Linux process lifecycle integration; no ADB or Qt page execution.

Run only in a disposable container with this runtime mounted read-only and a
fresh writable evidence directory. Actual C fixture processes have a 9-second
self deadline. The Python experiment has an 8-second alarm plus bounded cleanup.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

RUNTIME = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
import safety


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def live(expected):
    try:
        current = safety.identity(expected['pid'])
    except OSError as exc:
        if exc.errno in (2, 3):
            return False
        raise
    return all(current[key] == expected[key] for key in ('pid', 'starttime', 'exe'))


def wait_absent(expected, timeout=1, exits=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(expected['pid'], os.WNOHANG)
            if waited == expected['pid'] and exits is not None:
                if os.WIFEXITED(status):
                    exits[waited] = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exits[waited] = -os.WTERMSIG(status)
        except (ChildProcessError, OSError):
            pass
        if not live(expected):
            return True
        time.sleep(.02)
    return not live(expected)


def own_child_cleanup(child, expected):
    if child is None:
        return
    if child.poll() is None and expected is not None and live(expected):
        os.kill(expected['pid'], signal.SIGTERM)
    try:
        child.wait(timeout=.5)
    except subprocess.TimeoutExpired:
        if expected is not None and live(expected):
            os.kill(expected['pid'], signal.SIGKILL)
        child.wait(timeout=.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    require(output.is_dir(), 'Fresh output directory must already exist')
    require(not list(output.iterdir()), 'Evidence directory must be empty')
    started = time.monotonic()
    result = {'schema': 'p011.browser.host-process-integration.v1',
              'tier': 'HOST_ONLY', 'device_test': False, 'qt_page_test': False,
              'passed': False, 'runtime_safety_sha256': safety.digest(str(RUNTIME / 'safety.py')),
              'test_runner_sha256': safety.digest(str(pathlib.Path(__file__).resolve()))}
    root = pathlib.Path(tempfile.mkdtemp(prefix='p011-host-process-'))
    candidate = str(root / 'candidate')
    (root / 'candidate/bin').mkdir(parents=True)
    (root / 'candidate/libexec').mkdir()
    binary = root / 'candidate/bin/p011-browser-probe'
    helper = root / 'candidate/libexec/QtWebEngineProcess'
    sentinel_path = root / 'unrelated-sentinel'
    child = sentinel = None
    leader = sentinel_identity = escaped = None
    handles = []
    def deadline(signum, frame):
        raise TimeoutError('HOST_ONLY experiment deadline reached')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(8)
    try:
        compiler = subprocess.run(['cc', '-std=c99', '-O2', '-Wall', '-Wextra',
                                   str(RUNTIME / 'tests/host_process_fixture.c'), '-o', str(binary)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        (output / 'compiler.stdout.raw').write_bytes(compiler.stdout)
        (output / 'compiler.stderr.raw').write_bytes(compiler.stderr)
        result['compiler_exit'] = compiler.returncode
        require(compiler.returncode == 0, 'C fixture compilation failed')
        shutil.copy2(str(binary), str(helper))
        shutil.copy2(str(binary), str(sentinel_path))
        result['fixture_sha256'] = safety.digest(str(binary))
        result['fixture_source_sha256'] = safety.digest(str(RUNTIME / 'tests/host_process_fixture.c'))
        require(safety.private_processes(candidate) == [], 'Private fixture path unexpectedly active')
        for stem in ('browser', 'unrelated-sentinel'):
            for stream in ('stdout', 'stderr'):
                handles.append(open(str(output / (stem + '.' + stream + '.raw')), 'xb'))
        child = subprocess.Popen([str(binary), '--helper', str(helper)],
                                 stdout=handles[0], stderr=handles[1],
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        leader = safety.identity(child.pid)
        sentinel = subprocess.Popen([str(sentinel_path), '--sentinel'],
                                    stdout=handles[2], stderr=handles[3],
                                    stdin=subprocess.DEVNULL, start_new_session=True)
        sentinel_identity = safety.identity(sentinel.pid)
        require(leader['group'] == leader['pid'] == leader['session'], 'Main fixture lacks its own group/session')
        tracked = {(leader['pid'], leader['starttime'], leader['exe']): leader}
        ready_deadline = time.monotonic() + 1.5
        while time.monotonic() < ready_deadline:
            rows = safety.track_descendants(candidate, leader, tracked, os.getuid())
            helpers = [row for row in rows if row['exe'] == str(helper)
                       and row['session'] == row['pid'] and row['group'] == row['pid']
                       and (row['pid'], row['starttime'], row['exe']) in tracked]
            if helpers:
                escaped = helpers[0]
                break
            time.sleep(.02)
        require(escaped is not None, 'setsid helper was not observed and linked to the live main fixture')
        require(escaped['group'] != leader['group'], 'Helper did not escape the main process group')
        require(all(row['pid'] != sentinel.pid for row in tracked.values()), 'Unrelated sentinel entered ownership inventory')
        result['leader'] = leader
        result['escaped_descendant'] = escaped
        result['tracked_before_cleanup'] = list(tracked.values())
        result['group_term_targets'] = safety.signal_owned_group(candidate, leader, signal.SIGTERM)
        result['main_exit'] = child.wait(timeout=1)
        require(result['main_exit'] == 0, 'Main fixture did not handle group TERM cleanly')
        require(live(escaped), 'Escaped helper unexpectedly closed during group TERM')
        result['escaped_survived_group_term'] = True
        require(sentinel.poll() is None and live(sentinel_identity), 'Group TERM harmed the unrelated sentinel')
        result['escaped_pid_term_target'] = safety.signal_owned_pid(candidate, escaped, os.getuid(), signal.SIGTERM)
        descendant_exits = {}
        require(wait_absent(escaped, 1, descendant_exits), 'Identity-checked escaped descendant remained alive')
        result['escaped_exit'] = descendant_exits.get(escaped['pid'])
        require(result['escaped_exit'] == 0, 'Escaped helper clean exit status was not observed')
        result['remaining_private_processes'] = safety.private_processes(candidate)
        require(result['remaining_private_processes'] == [], 'Fixture candidate processes remain active')
        require(sentinel.poll() is None and live(sentinel_identity), 'PID fallback harmed the unrelated sentinel')
        result['unrelated_sentinel_survived_all_browser_cleanup'] = True
        result['unrelated_sentinel_identity'] = sentinel_identity
        result['passed'] = True
    except Exception as exc:
        result['error_type'] = type(exc).__name__
        result['error'] = str(exc)
    finally:
        signal.alarm(0)
        # Every C fixture also has its own 9-second backstop. This cleanup only
        # targets immutable identities in the unique, newly created temp tree.
        if escaped is not None and live(escaped):
            safety.signal_owned_pid(candidate, escaped, os.getuid(), signal.SIGKILL)
            wait_absent(escaped, .5)
        own_child_cleanup(child, leader)
        own_child_cleanup(sentinel, sentinel_identity)
        for row in safety.private_processes(candidate):
            safety.signal_owned_pid(candidate, row, os.getuid(), signal.SIGKILL)
            wait_absent(row, .5)
        result['final_private_processes'] = safety.private_processes(candidate)
        result['sentinel_final_exit'] = sentinel.poll() if sentinel is not None else None
        result['all_test_processes_closed'] = (result['final_private_processes'] == []
                                               and (child is None or child.poll() is not None)
                                               and (sentinel is None or sentinel.poll() is not None))
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
        result['passed'] = result['passed'] and result['all_test_processes_closed'] and result['elapsed_seconds'] < 10
        for handle in handles:
            handle.close()
        (output / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        # Compiler/products are disposable container tmpfs data. Evidence stays.
        shutil.rmtree(str(root))
    print('HOST_ONLY_RESULT=' + json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
