#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Temporary MenuLab trial supervisor, Python 3.5+, Linux only.

No stock executable/startup file is overwritten. The known restart-loop process
is paused, its current Z03 child is asked to terminate, and a candidate copy is
started once. An independent, detached guardian resumes the stock loop after the
trial, a worker failure or a stop request. No blanket killall or PID-only kills.

This is NOT a sandbox: the unchanged native app can still use its normal services
and update app/user data. A kernel hang or simultaneous loss of the guardian and
ADB cannot be repaired by this script. Normal reboot remains the fallback.
"""
import os
import sys
import time
import signal
import stat
import subprocess
import hashlib
import ctypes as C

import p011_json as json
import menu_policy as P

ROOT = os.path.realpath(os.path.dirname(__file__))
LOGS = os.path.join(ROOT, 'logs')
SELF = os.path.join(ROOT, 'menu_trial.py')
CANDIDATE = os.path.join(ROOT, 'Z03')
PAGES = os.path.join(ROOT, 'pages')
REQUEST_STOP = False
DEAD = ('Z', 'X', 'x')


def read_file(path, limit=1024 * 1024):
    with open(path, 'rb') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('File over limit: ' + path)
    return data


def read_text(path, limit=1024 * 1024):
    return read_file(path, limit).decode('utf-8', 'replace')


def atomic_text(path, text):
    tmp = path + '.new-' + str(os.getpid())
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


def ensure_logs():
    if not os.path.isdir(LOGS):
        os.mkdir(LOGS, 0o700)


def log(text):
    ensure_logs()
    line = time.strftime('%H:%M:%S') + ' ' + str(text) + '\n'
    # One append per record. Worker and guardian deliberately have separate roles.
    with open(os.path.join(LOGS, 'trial.log'), 'a', encoding='utf-8') as f:
        f.write(line)
    print(line.rstrip(), flush=True)


def status(text):
    atomic_text(os.path.join(LOGS, 'status.txt'), text + '\n')
    log(text)


def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def boot_id():
    return read_text('/proc/sys/kernel/random/boot_id', 128).strip()


def process(pid):
    """Read state/starttime first. A zombie need not have readable exe/cmdline."""
    try:
        raw = read_text('/proc/%d/stat' % int(pid), 8192)
        split = raw.rfind(')')
        fields = raw[split + 2:].split()
        if split < 0 or len(fields) < 20:
            return None
        result = {'pid': int(pid), 'state': fields[0], 'ppid': int(fields[1]),
                  'pgrp': int(fields[2]), 'sid': int(fields[3]),
                  'start': int(fields[19]), 'exe': '', 'args': []}
        try:
            result['exe'] = os.readlink('/proc/%d/exe' % int(pid))
            rawargs = read_file('/proc/%d/cmdline' % int(pid), 65536)
            result['args'] = [os.fsdecode(x) for x in rawargs.split(b'\0') if x]
        except OSError:
            pass
        return result
    except (OSError, ValueError):
        return None


def processes():
    values = []
    for name in os.listdir('/proc'):
        if name.isdigit():
            p = process(int(name))
            if p:
                values.append(p)
    return values


def alive(p):
    return p is not None and p['state'] not in DEAD


def identity(p):
    return '%d %d' % (p['pid'], p['start'])


def record_identity(name, p):
    atomic_text(os.path.join(LOGS, name + '.ident'), identity(p) + '\n')


def get_identity(name):
    try:
        v = read_text(os.path.join(LOGS, name + '.ident'), 128).split()
        if len(v) != 2:
            return None
        return {'pid': int(v[0]), 'start': int(v[1])}
    except (OSError, ValueError):
        return None


def refresh(saved):
    if saved is None:
        return None
    p = process(saved['pid'])
    return p if p and p['start'] == saved['start'] else None


def signal_exact(saved, sig, expected_exe=None):
    p = refresh(saved)
    if not alive(p):
        return False
    if expected_exe is not None and p['exe'] != expected_exe:
        raise RuntimeError('Executable identity changed; signal refused.')
    if p['pid'] <= 1 or p['pid'] == os.getpid():
        raise RuntimeError('Invalid target PID; signal refused.')
    # Linux 4.14 has no pidfd API: verify starttime immediately before kill.
    os.kill(p['pid'], sig)
    return True


def launcher_matches(p):
    if not alive(p):
        return False
    for arg in p['args'][:3]:
        if arg == P.LAUNCHER:
            return True
    return False


def stock_processes():
    path = os.path.realpath(P.STOCK)
    return [p for p in processes() if alive(p) and p['exe'] == path]


def environment(p):
    data = read_file('/proc/%d/environ' % p['pid'], 131072)
    env = {}
    for item in data.split(b'\0'):
        if b'=' in item:
            k, v = item.split(b'=', 1)
            env[os.fsdecode(k)] = os.fsdecode(v)
    return env


def check_lock():
    if os.path.lexists(P.LOCK):
        raise RuntimeError('Another/stale trial lock exists. Use Stop/Collect first; do not delete it blindly.')


def inspect_device():
    ensure_logs()
    if os.geteuid() != 0:
        raise RuntimeError('root ADB is required.')
    if not (sys.version_info >= (3, 5)):
        raise RuntimeError('Python 3.5 or later is required.')
    check_lock()
    if os.path.lexists(P.MENU_LINK):
        raise RuntimeError(P.MENU_LINK + ' already exists. Nothing will overwrite that path.')
    for path, expected in ((P.STOCK, P.ORIGINAL_SHA256),
                           (P.LAUNCHER, P.LAUNCHER_SHA256),
                           (CANDIDATE, P.CANDIDATE_SHA256)):
        if not os.path.isfile(path) or hash_file(path) != expected:
            raise RuntimeError('Hash mismatch/missing file: ' + path)
    for name, expected in P.PAGE_HASHES.items():
        if hash_file(os.path.join(PAGES, name)) != expected:
            raise RuntimeError('Example page mismatch: ' + name)
    capture_dir = os.path.join(LOGS, 'screenshots')
    if not os.path.exists(capture_dir):
        os.mkdir(capture_dir, 0o700)
    if os.path.islink(capture_dir) or not os.path.isdir(capture_dir):
        raise RuntimeError('Unsafe local capture directory.')
    capture_link = os.path.join(PAGES, '_captures')
    if not os.path.lexists(capture_link):
        os.symlink(capture_dir, capture_link)
    elif not os.path.islink(capture_link) or os.readlink(capture_link) != capture_dir:
        raise RuntimeError('Capture alias already points elsewhere.')
    current = stock_processes()
    if len(current) != 1:
        raise RuntimeError('Expected one live original Z03; found %d.' % len(current))
    app = current[0]
    if app['state'] in ('T', 't', 'D'):
        raise RuntimeError('Original app is stopped/traced/uninterruptible; no trial.')
    parent = process(app['ppid'])
    if not launcher_matches(parent) or parent['state'] in ('T', 't', 'D'):
        raise RuntimeError('Original Z03 parent is not the expected live zyb_z03_launch.sh. No signals sent.')
    launchers = [p for p in processes() if launcher_matches(p)]
    if len(launchers) != 1 or launchers[0]['pid'] != parent['pid']:
        raise RuntimeError('Ambiguous restart-loop process; no signals sent.')
    if app['args'][1:] != ['-platform', 'wayland']:
        raise RuntimeError('Unexpected Z03 arguments; no trial: ' + repr(app['args'][1:]))
    allp = processes()
    if any('p011_lab.py' in a for p in allp for a in p['args']):
        raise RuntimeError('PlayLab is still running. Close its own window first.')
    env = environment(app)
    xdg = env.get('XDG_RUNTIME_DIR', '')
    display = env.get('WAYLAND_DISPLAY', 'wayland-0')
    if not xdg or '/' in display or '\n' in xdg:
        raise RuntimeError('Unexpected Wayland environment; no trial.')
    sock = os.path.join(xdg, display)
    if not stat.S_ISSOCK(os.stat(sock).st_mode):
        raise RuntimeError('Wayland socket is unavailable.')
    cwd = os.readlink('/proc/%d/cwd' % app['pid'])
    # Read-only resource checks; no camera/network/DB probing.
    if not os.access(CANDIDATE, os.X_OK):
        raise RuntimeError('Candidate is not executable.')
    fs = os.statvfs(ROOT)
    if fs.f_flag & getattr(os, 'ST_NOEXEC', 8):
        raise RuntimeError('Temporary filesystem is mounted noexec; nothing will be remounted.')
    if fs.f_bavail * fs.f_frsize < 24 * 1024 * 1024:
        raise RuntimeError('Temporary directory has under 24 MiB free.')
    details = {'schema': 'p011.menucheck.v0.3', 'ok': True,
               'stock': app, 'launcher': parent, 'cwd': cwd,
               'display_environment': {k: env.get(k, '') for k in
                 ('HOME', 'XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'QT_QPA_PLATFORM')},
               'original_sha256': P.ORIGINAL_SHA256,
               'candidate_sha256': P.CANDIDATE_SHA256,
               'launcher_sha256': P.LAUNCHER_SHA256,
               'note': 'Read-only preflight, not a QML runtime test. Full process environment is not saved.'}
    atomic_text(os.path.join(LOGS, 'inspection.json'), json.dumps(details, indent=2))
    log('CHECK_OK: original PID=%d, restart-loop PID=%d; hashes and Wayland verified.' % (app['pid'], parent['pid']))
    return app, parent, env, cwd


def request_exit(signum, frame):
    global REQUEST_STOP
    REQUEST_STOP = True


def stop_requested():
    return REQUEST_STOP or os.path.isfile(os.path.join(LOGS, 'stop.request'))


def same_boot():
    return read_text(os.path.join(LOGS, 'boot-id.txt'), 128).strip() == boot_id()


def trial_worker(seconds):
    """The guardian is running before this worker may pause the stock loop."""
    if not same_boot() or not os.path.isfile(os.path.join(LOGS, 'guardian.ready')):
        raise RuntimeError('Guardian/boot identity was not confirmed.')
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, request_exit)
    parent = refresh(get_identity('launcher'))
    app = refresh(get_identity('original'))
    if not launcher_matches(parent) or not alive(app) or app['ppid'] != parent['pid']:
        raise RuntimeError('Startup process topology changed before trial.')
    if app['exe'] != os.path.realpath(P.STOCK):
        raise RuntimeError('Stock executable identity changed.')
    env = environment(app)                 # memory only, never written to reports
    cwd = os.readlink('/proc/%d/cwd' % app['pid'])
    if os.path.lexists(P.MENU_LINK):
        raise RuntimeError('External-page path appeared after preflight; stopped.')
    os.symlink(PAGES, P.MENU_LINK)          # new temporary alias, never overwrites
    atomic_text(os.path.join(LOGS, 'link.created'), PAGES + '\n')
    if stop_requested():
        return
    # Arm a recovery marker before the stop operation, for exception-safe cleanup.
    atomic_text(os.path.join(LOGS, 'pause.attempted'), identity(parent) + '\n')
    signal_exact(parent, signal.SIGSTOP)
    until = time.monotonic() + 2.0
    while time.monotonic() < until:
        now = refresh(parent)
        if now and now['state'] in ('T', 't'):
            break
        time.sleep(0.04)
    else:
        raise RuntimeError('Restart loop did not enter stopped state.')
    status('RESTART_LOOP_PAUSED')
    if stop_requested():
        return
    current = stock_processes()
    if len(current) != 1 or current[0]['pid'] != app['pid'] or current[0]['start'] != app['start']:
        raise RuntimeError('Stock app changed while pausing loop.')
    signal_exact(app, signal.SIGTERM, os.path.realpath(P.STOCK))
    status('ORIGINAL_TERM_SENT: waiting for exit; original app is never SIGKILLed.')
    until = time.monotonic() + 8
    while time.monotonic() < until and alive(refresh(app)):
        if stop_requested():
            return
        time.sleep(0.05)
    if alive(refresh(app)):
        raise RuntimeError('Original Z03 did not exit in 8 seconds; candidate NOT started.')
    if stock_processes():
        raise RuntimeError('A second original app appeared; candidate NOT started.')
    if not launcher_matches(refresh(parent)):
        raise RuntimeError('Restart-loop process disappeared; candidate NOT started.')
    # Avoid persistent QML bytecode cache and candidate core dumps. Process-only.
    env.pop('QML_FORCE_DISK_CACHE', None)
    env['QML_DISABLE_DISK_CACHE'] = '1'
    env['QT_LOGGING_TO_CONSOLE'] = '1'
    # python-resource is absent in the inspected image. Use libc with the
    # native rlim_t width; Linux RLIMIT_CORE=4. Changes only this worker/child.
    class RLimit(C.Structure):
        _fields_ = [('soft', C.c_ulong), ('hard', C.c_ulong)]
    libc = C.CDLL(None, use_errno=True)
    libc.setrlimit.argtypes = [C.c_int, C.POINTER(RLimit)]
    libc.setrlimit.restype = C.c_int
    limit = RLimit(0, 0)
    if libc.setrlimit(4, C.byref(limit)) != 0:
        raise OSError(C.get_errno(), 'Cannot disable candidate core dump')
    with open(os.devnull, 'rb') as inp, open(os.path.join(LOGS, 'candidate.log'), 'ab', buffering=0) as out:
        child = subprocess.Popen([CANDIDATE, '-platform', 'wayland'], cwd=cwd, env=env,
                                 stdin=inp, stdout=out, stderr=out,
                                 close_fds=True, start_new_session=True)
    child_info = process(child.pid)
    if not alive(child_info) or child_info['exe'] != CANDIDATE:
        # The child can exit before metadata is sampled; no false RUNNING result.
        raise RuntimeError('Candidate exited or could not be identified during startup.')
    record_identity('candidate', child_info)
    status('CANDIDATE_RUNNING: PID=%d; test window=%ds; inspect the pen screen now.' % (child.pid, seconds))
    started = time.monotonic()
    while child.poll() is None and time.monotonic() - started < seconds:
        if stop_requested():
            log('STOP_REQUEST_RECEIVED')
            return
        p = refresh(parent)
        if not launcher_matches(p) or p['state'] not in ('T', 't'):
            raise RuntimeError('Stock restart-loop changed/resumed unexpectedly.')
        if stock_processes():
            raise RuntimeError('Unexpected parallel stock app; ending trial.')
        if os.path.getsize(os.path.join(LOGS, 'candidate.log')) > 8 * 1024 * 1024:
            raise RuntimeError('Candidate log reached 8 MiB; ending trial.')
        capture_dir = os.path.join(LOGS, 'screenshots')
        captured_bytes = sum(os.path.getsize(os.path.join(capture_dir, n))
                             for n in os.listdir(capture_dir)
                             if n.endswith('.png'))
        if captured_bytes > 24 * 1024 * 1024:
            raise RuntimeError('Screenshots reached 24 MiB; ending trial.')
        time.sleep(0.2)
    if child.poll() is not None:
        atomic_text(os.path.join(LOGS, 'candidate.exit'), str(child.returncode) + '\n')
        status('CANDIDATE_EXITED: code=%d; guardian will restore stock.' % child.returncode)
    else:
        status('TEST_WINDOW_ENDED: guardian will restore stock.')


def candidate_group():
    """Only the uniquely named candidate and its private session are eligible."""
    allp = processes()
    roots = [p for p in allp if alive(p) and p['exe'] == CANDIDATE]
    saved = get_identity('candidate')
    validroot = refresh(saved)
    if alive(validroot) and validroot['exe'] != CANDIDATE:
        raise RuntimeError('Candidate PID was reused/exec changed; no broad cleanup.')
    ids = [(p['sid'], p['start']) for p in roots if p['sid'] == p['pid']]
    if saved:
        # The PID was written only for a start_new_session candidate.
        ids.append((saved['pid'], saved['start']))
    owned = []
    for p in allp:
        if not alive(p):
            continue
        if p['exe'] == CANDIDATE or any(p['sid'] == sid and p['start'] >= start for sid, start in ids):
            owned.append(p)
    return owned


def cleanup_candidate():
    owned = candidate_group()
    for p in owned:
        signal_exact(p, signal.SIGTERM)
    until = time.monotonic() + 5
    while time.monotonic() < until and candidate_group():
        time.sleep(0.1)
    left = candidate_group()
    for p in left:
        log('CANDIDATE_FORCE_EXIT: PID=%d (not original app)' % p['pid'])
        signal_exact(p, signal.SIGKILL)
    until = time.monotonic() + 3
    while time.monotonic() < until and candidate_group():
        time.sleep(0.1)
    if candidate_group():
        raise RuntimeError('Candidate remains uninterruptible; cannot safely start a parallel app. Normal reboot required.')


def cleanup_link():
    if os.path.islink(P.MENU_LINK) and os.readlink(P.MENU_LINK) == PAGES:
        os.unlink(P.MENU_LINK)
        log('TEMP_MENU_ALIAS_REMOVED')


def restore_stock(env=None, cwd=None):
    if not same_boot():
        raise RuntimeError('Boot identity changed; no stale-PID restore allowed.')
    status('RESTORING_STOCK')
    cleanup_candidate()
    cleanup_link()
    parent = refresh(get_identity('launcher'))
    if launcher_matches(parent):
        signal_exact(parent, signal.SIGCONT)
        log('RESTART_LOOP_RESUMED: PID=%d' % parent['pid'])
    else:
        # Never restart blindly if another stock app/launcher is already active.
        loops = [p for p in processes() if launcher_matches(p)]
        if not loops and not stock_processes():
            if env is None or cwd is None or hash_file(P.LAUNCHER) != P.LAUNCHER_SHA256:
                raise RuntimeError('Original launcher disappeared; normal reboot required (no guessed restart).')
            with open(os.devnull, 'rb') as inp, open(os.path.join(LOGS, 'restore-launcher.log'), 'ab') as out:
                proc = subprocess.Popen(['/bin/sh', P.LAUNCHER], cwd=cwd, env=env,
                    stdin=inp, stdout=out, stderr=out, start_new_session=True, close_fds=True)
            log('ORIGINAL_LAUNCHER_RESTARTED: PID=%d; unchanged stock script.' % proc.pid)
    until = time.monotonic() + 20
    confirmed = None
    since = None
    while time.monotonic() < until:
        stock = stock_processes()
        if len(stock) == 1 and launcher_matches(process(stock[0]['ppid'])) and stock[0]['state'] not in ('T','t','D'):
            key = identity(stock[0])
            if confirmed != key:
                confirmed, since = key, time.monotonic()
            if time.monotonic() - since >= 2:
                unchanged = hash_file(P.STOCK) == P.ORIGINAL_SHA256 and hash_file(P.LAUNCHER) == P.LAUNCHER_SHA256
                if not unchanged:
                    raise RuntimeError('Original files changed; preserve logs and investigate.')
                record_identity('restored-stock', stock[0])
                status('RESTORED_STOCK_PROCESS: PID=%d; original files unchanged. Visual recovery still needs user confirmation.' % stock[0]['pid'])
                return True
        else:
            confirmed, since = None, None
        time.sleep(0.2)
    raise RuntimeError('No stable original Z03 observed in 20 seconds; keep ADB, use normal reboot if needed.')


def release_lock():
    if os.path.islink(P.LOCK) and os.readlink(P.LOCK) == ROOT:
        os.unlink(P.LOCK)


def guardian(seconds):
    global REQUEST_STOP
    REQUEST_STOP = False
    worker = None
    env, cwd = None, None
    successful_restore = False
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, request_exit)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        if not same_boot() or not os.path.islink(P.LOCK) or os.readlink(P.LOCK) != ROOT:
            raise RuntimeError('Guardian session/boot identity mismatch.')
        app = refresh(get_identity('original'))
        parent = refresh(get_identity('launcher'))
        if not alive(app) or not launcher_matches(parent) or app['ppid'] != parent['pid']:
            raise RuntimeError('Original process changed before guardian armed.')
        env = environment(app)
        cwd = os.readlink('/proc/%d/cwd' % app['pid'])
        record_identity('guardian', process(os.getpid()))
        atomic_text(os.path.join(LOGS, 'guardian.ready'), 'READY\n')
        status('GUARDIAN_ARMED: timeout and rollback run ON the pen, not in PowerShell.')
        if stop_requested():
            return
        with open(os.devnull, 'rb') as inp, open(os.path.join(LOGS, 'worker.log'), 'ab') as out:
            worker = subprocess.Popen([sys.executable, '-B', SELF, 'worker', str(seconds)],
                stdin=inp, stdout=out, stderr=out, close_fds=True, start_new_session=True)
        record_identity('worker', process(worker.pid))
        deadline = time.monotonic() + seconds + 25
        while worker.poll() is None and time.monotonic() < deadline and not stop_requested():
            time.sleep(0.2)
        if stop_requested():
            log('GUARDIAN_STOP_REQUEST')
        elif worker.poll() is None:
            log('GUARDIAN_DEADLINE: worker did not finish; recovery follows.')
        else:
            log('WORKER_EXIT: %d' % worker.returncode)
    except Exception as exc:
        log('GUARDIAN_ERROR: %s: %s' % (type(exc).__name__, str(exc)))
    finally:
        # Stop worker first so it cannot start another candidate during recovery.
        worker_stopped = True
        if worker is not None and worker.poll() is None:
            try:
                worker.terminate()
                try:
                    worker.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait(timeout=2)
            except Exception as exc:
                worker_stopped = (worker.poll() is not None)
                log('WORKER_CLEANUP_ERROR: ' + str(exc))
        try:
            if not worker_stopped:
                raise RuntimeError('Worker still alive; unsafe to resume stock concurrently. Normal reboot required.')
            successful_restore = restore_stock(env, cwd)
        except Exception as exc:
            status('RECOVERY_NEEDS_ATTENTION: %s: %s' % (type(exc).__name__, str(exc)))
        if successful_restore:
            release_lock()
        atomic_text(os.path.join(LOGS, 'finished'), 'RESTORED\n' if successful_restore else 'RECOVERY_NEEDS_ATTENTION\n')


def start_trial(seconds):
    if not 60 <= seconds <= 300:
        raise RuntimeError('Trial duration must be between 60 and 300 seconds.')
    app, parent, env, cwd = inspect_device()
    if os.path.exists(os.path.join(LOGS, 'guardian.ready')):
        raise RuntimeError('This session was already used. Start a fresh session.')
    os.symlink(ROOT, P.LOCK)        # atomic exclusivity; raises if another trial won
    proc = None
    try:
        record_identity('original', app)
        record_identity('launcher', parent)
        atomic_text(os.path.join(LOGS, 'boot-id.txt'), boot_id() + '\n')
        with open(os.devnull, 'rb') as inp, open(os.path.join(LOGS, 'guardian.log'), 'ab') as out:
            proc = subprocess.Popen([sys.executable, '-B', SELF, 'guardian', str(seconds)],
                stdin=inp, stdout=out, stderr=out, close_fds=True, start_new_session=True)
        # No pipes/terminal are inherited by the guardian, so ADB may disconnect.
        until = time.monotonic() + 5
        while time.monotonic() < until:
            if os.path.isfile(os.path.join(LOGS, 'guardian.ready')):
                print('TRIAL_STARTED: guardian PID=%d; seconds=%d' % (proc.pid, seconds), flush=True)
                return
            if proc.poll() is not None:
                raise RuntimeError('Guardian exited before arming; see guardian.log.')
            time.sleep(0.05)
        raise RuntimeError('Guardian did not arm within 5 seconds; stop requested.')
    except Exception:
        if proc is not None and proc.poll() is None:
            atomic_text(os.path.join(LOGS, 'stop.request'), 'start-failed\n')
        else:
            release_lock()
        raise


def print_status():
    p = os.path.join(LOGS, 'status.txt')
    print(read_text(p, 8192).strip() if os.path.exists(p) else 'NO_TRIAL_STARTED')
    if os.path.isfile(os.path.join(LOGS, 'finished')):
        print('FINISHED: ' + read_text(os.path.join(LOGS, 'finished'), 256).strip())


def stop_trial():
    if os.path.isfile(os.path.join(LOGS, 'finished')) and read_text(os.path.join(LOGS, 'finished'), 256).strip() == 'RESTORED':
        print_status()
        return
    if not os.path.isfile(os.path.join(LOGS, 'boot-id.txt')):
        print('NO_TRIAL_STARTED')
        return
    if not same_boot():
        raise RuntimeError('Device rebooted. No stale process signals will be sent.')
    atomic_text(os.path.join(LOGS, 'stop.request'), 'user-request\n')
    p = refresh(get_identity('guardian'))
    if alive(p) and SELF in p['args'] and 'guardian' in p['args']:
        print('STOP_REQUESTED: guardian will stop candidate and resume original loop.')
        return
    # If the guardian died, do not race a live worker; identity checks remain.
    worker = refresh(get_identity('worker'))
    if alive(worker):
        if SELF not in worker['args'] or 'worker' not in worker['args']:
            raise RuntimeError('Worker identity changed; no emergency signals sent.')
        signal_exact(worker, signal.SIGKILL)
        until = time.monotonic() + 2
        while time.monotonic() < until and alive(refresh(worker)):
            time.sleep(0.05)
        if alive(refresh(worker)):
            raise RuntimeError('Worker did not exit. Normal reboot needed.')
    print('GUARDIAN_MISSING: attempting identity-checked local recovery.')
    if restore_stock():
        release_lock()
        atomic_text(os.path.join(LOGS, 'finished'), 'RESTORED\n')


def main():
    ensure_logs()
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == 'inspect':
        inspect_device()
    elif mode == 'start':
        start_trial(int(sys.argv[2]))
    elif mode == 'guardian':
        guardian(int(sys.argv[2]))
    elif mode == 'worker':
        trial_worker(int(sys.argv[2]))
    elif mode == 'status':
        print_status()
    elif mode == 'stop':
        stop_trial()
    else:
        raise RuntimeError('Use inspect/start/status/stop. Internal guardian/worker are not standalone commands.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        log('ERROR: %s: %s' % (type(exc).__name__, str(exc)))
        sys.exit(1)
