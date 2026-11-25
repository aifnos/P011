# -*- coding: utf-8 -*-
"""Detached finite browser owner. Only this trial's identity-checked group is signalled."""
import argparse
import os
import signal
import socket
import stat
import subprocess
import sys
import time

import p011_json as J
from safety import (acquire_lease, browser_environment, canonical_identity, checked_group, control_directory,
                    identity, load_baseline, owned_directory, private_processes,
                    release_lease, same_stock, signal_owned_group, signal_owned_pid,
                    stock_snapshot, stop_requested, track_descendants,
                    trial_mode, validate_app_directory, validate_child_user, validate_paths,
                    write_new)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--uid', type=int)
    parser.add_argument('--gid', type=int)
    parser.add_argument('--offline-no-sandbox', action='store_true',
                        help='Explicit default qrc fixture only; no URL or automatic fallback')
    parser.add_argument('--public-site', choices=('baidu', 'bilibili'),
                        help='Fixed public site; requires --public-no-sandbox')
    parser.add_argument('--public-no-sandbox', action='store_true',
                        help='Explicit fixed-site compatibility trial; requires --public-site')
    parser.add_argument('--interactive', action='store_true',
                        help='User-controlled browser opened from the settings entry')
    parser.add_argument('--interactive-no-sandbox', action='store_true',
                        help='Explicit interactive no-sandbox mode; requires --interactive')
    parser.add_argument('--shell-integration', choices=('wl-shell', 'xdg-shell-v6', 'xdg-shell'), default='wl-shell')
    args = parser.parse_args()
    maximum = 1800 if args.interactive else 120
    if not 1 <= args.seconds <= maximum:
        parser.error('--seconds must be between 1 and ' + str(maximum))
    if args.uid is None:
        args.uid = os.geteuid()
    if args.gid is None:
        args.gid = os.getegid() if args.uid == os.geteuid() else args.uid
    validate_child_user(args.uid, args.gid)
    try:
        trial_mode(args.offline_no_sandbox, args.public_site, args.public_no_sandbox,
                   args.interactive, args.interactive_no_sandbox)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def browser_command(binary, app, seconds, offline_no_sandbox=False,
                    public_site=None, public_no_sandbox=False,
                    interactive=False, interactive_no_sandbox=False):
    mode = trial_mode(offline_no_sandbox, public_site, public_no_sandbox,
                      interactive, interactive_no_sandbox)
    command = [binary, '--session', app, '--seconds', str(seconds)]
    if mode['public_site'] is not None:
        # The app maps only these two labels to fixed HTTPS URLs. No arbitrary
        # URL, page script, shell command or inherited argument is forwarded.
        command.extend(['--public-site', mode['public_site']])
    if mode['interactive']:
        command.append('--interactive')
    return command


def set_child_oom_priority():
    """Only this preexec child's score changes; descendants inherit it."""
    try:
        descriptor = os.open('/proc/self/oom_score_adj', os.O_WRONLY)
        try:
            if os.write(descriptor, b'500\n') != 4:
                os._exit(125)
        finally:
            os.close(descriptor)
    except OSError:
        os._exit(125)


def child_preexec(uid, gid, birth_fd):
    def prepare():
        import ctypes
        os.umask(0o077)
        # The target Python omits resource. Linux ARM RLIMIT_CORE is 4; this is
        # the same libc-only mechanism used by the existing P011 GLES probe.
        class Limit(ctypes.Structure):
            _fields_ = [('cur', ctypes.c_ulong), ('max', ctypes.c_ulong)]
        libc = ctypes.CDLL('libc.so.6', use_errno=True)
        libc.setrlimit.argtypes = [ctypes.c_int, ctypes.POINTER(Limit)]
        libc.setrlimit.restype = ctypes.c_int
        if libc.setrlimit(4, ctypes.byref(Limit(0, 0))) != 0:
            os._exit(125)
        # Linux RLIMIT_FSIZE=1 limits each child's raw log/output file as well
        # as captures, preserving the reserved userdata space on a noisy crash.
        if libc.setrlimit(1, ctypes.byref(Limit(16 * 1024 * 1024, 16 * 1024 * 1024))) != 0:
            os._exit(125)
        # Prefer sacrificing this finite browser group if its memory peak
        # exhausts the small device. Never adjust a vendor PID or global knob.
        set_child_oom_priority()
        # Capture immutable birth identity before exec. Popen confirms successful
        # exec, but a failing browser may exit before the parent reads /proc.
        os.write(birth_fd, (repr(identity(os.getpid())) + '\n').encode('utf-8'))
        os.close(birth_fd)
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        if os.geteuid() == 0 or os.geteuid() != uid or os.getegid() != gid:
            os._exit(126)
    return prepare


def verify_executable(candidate, relative):
    path = candidate + '/' + relative
    control_directory(os.path.dirname(path))
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or not info.st_mode & 0o111:
        raise ValueError('Unsafe browser executable')
    return path


def cleanup_group(candidate, leader, child, result):
    """TERM then KILL, with a fresh identity check before either group signal."""
    if leader is None:
        return
    # Reap an already exited leader before checking /proc. This also handles the
    # normal child-exit path without mistaking a zombie for a live owner.
    if child is not None:
        child.poll()
    members = checked_group(candidate, leader)
    if members:
        result['term_members'] = signal_owned_group(candidate, leader, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if child is not None:
                child.poll()
            if not checked_group(candidate, leader):
                break
            time.sleep(0.1)
    if child is not None:
        child.poll()
    if checked_group(candidate, leader):
        result['kill_members'] = signal_owned_group(candidate, leader, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if child is not None:
                child.poll()
            if not checked_group(candidate, leader):
                break
            time.sleep(0.1)
    if child is not None:
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    result['remaining_group'] = checked_group(candidate, leader)


def cleanup_detached(candidate, leader, child, uid, tracked, result):
    """Close observed browser descendants even if Chromium called setsid()."""
    if leader is None:
        return
    for signum, allowance in ((signal.SIGTERM, 3), (signal.SIGKILL, 2)):
        rows = track_descendants(candidate, leader, tracked, uid)
        for row in rows:
            key = (row['pid'], row['starttime'], row['exe'])
            if key in tracked:
                sent = signal_owned_pid(candidate, tracked[key], uid, signum)
                if sent is not None:
                    result.setdefault('detached_pid_signals', []).append({'signal': int(signum), 'identity': sent})
        deadline = time.monotonic() + allowance
        while time.monotonic() < deadline:
            if child is not None:
                child.poll()
            if not track_descendants(candidate, leader, tracked, uid):
                return
            time.sleep(0.1)


def main(args=None):
    args = arguments() if args is None else args
    interactive = getattr(args, 'interactive', False)
    interactive_no_sandbox = getattr(args, 'interactive_no_sandbox', False)
    mode = trial_mode(args.offline_no_sandbox, args.public_site, args.public_no_sandbox,
                      interactive, interactive_no_sandbox)
    validate_paths(args.candidate, args.session)
    baseline = load_baseline(args.baseline, args.session)
    validate_child_user(args.uid, args.gid)
    app = validate_app_directory(args.session, args.uid, args.gid)
    result_path = args.session + '/result.json'
    if os.path.lexists(result_path):
        raise ValueError('Session already has a result')
    # Exclusive ownership. Never remove an old lock or reuse a finished session.
    write_new(args.session + '/guardian-owner.py', repr(identity(os.getpid())) + '\n')
    result = {'schema': 'p011.browser.runtime-result.v1', 'device_test': True,
              'candidate': args.candidate, 'session': args.session,
              'seconds': args.seconds, 'cleanup_allowance_seconds': 20,
              'child_max_file_bytes': 16 * 1024 * 1024,
              'child_oom_score_adj_requested': 500, 'child_oom_score_adj': None,
              'browser_uid': args.uid, 'browser_gid': args.gid,
              'original_processes_signalled': False, 'browser_exit': None,
              'started_epoch': time.time(), 'stop_requested': False,
              'timed_out': False, 'passed': False}
    result.update(mode)
    child = None
    leader = None
    connection = None
    birth_read = None
    birth_write = None
    lease = None
    lease_owner = None
    tracked = {}
    requested = [False]
    def request_stop(signum, frame):
        requested[0] = True
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, request_stop)
    before = None
    try:
        before = stock_snapshot()
        if not same_stock(baseline, before):
            raise ValueError('Current stock differs from this session baseline')
        lease, lease_owner = acquire_lease(args.candidate, args.session)
        if private_processes(args.candidate):
            raise ValueError('Candidate already has a live process')
        binary = verify_executable(args.candidate, 'bin/p011-browser-probe')
        verify_executable(args.candidate, 'libexec/QtWebEngineProcess')
        # Open only the fixed display socket before dropping browser privileges.
        # WAYLAND_SOCKET gives the child this connected FD without changing
        # permissions on /run/user/0 or the system Wayland socket.
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3)
        connection.connect('/run/user/0/wayland-0')
        connection.settimeout(None)
        env = browser_environment(args.candidate, args.session, connection.fileno(),
                                  args.shell_integration, args.offline_no_sandbox,
                                  args.public_site, args.public_no_sandbox,
                                  interactive, interactive_no_sandbox)
        command = browser_command(binary, app, args.seconds, args.offline_no_sandbox,
                                  args.public_site, args.public_no_sandbox,
                                  interactive, interactive_no_sandbox)
        birth_read, birth_write = os.pipe()
        with open(args.session + '/browser.stdout.raw', 'xb') as stdout, open(args.session + '/browser.stderr.raw', 'xb') as stderr:
            child = subprocess.Popen(command,
                                     cwd=app, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr,
                                     start_new_session=True, pass_fds=(connection.fileno(), birth_write),
                                     preexec_fn=child_preexec(args.uid, args.gid, birth_write))
            # Successful Popen exec confirms the preexec score write completed.
            result['child_oom_score_adj'] = 500
            os.close(birth_write)
            birth_write = None
            import ast
            raw_birth = os.read(birth_read, 8192)
            os.close(birth_read)
            birth_read = None
            birth = ast.literal_eval(raw_birth.decode('utf-8'))
            if birth['pid'] != child.pid or birth['session'] != child.pid or birth['group'] != child.pid:
                raise ValueError('Browser birth identity differs')
            leader = dict(birth, exe=binary, name=os.path.basename(binary)[:15])
            connection.close()
            connection = None
            try:
                observed = identity(child.pid)
                if observed['exe'] != binary or observed['starttime'] != birth['starttime'] or observed['session'] != child.pid or observed['group'] != child.pid:
                    raise ValueError('Browser launch identity differs')
                leader = observed
                result['browser_identity_source'] = 'live proc after successful exec'
            except OSError as exc:
                if exc.errno not in (2, 3):
                    raise
                result['browser_identity_source'] = 'preexec birth identity and Popen exec confirmation; process already exited'
            result['browser_identity'] = leader
            tracked[(leader['pid'], leader['starttime'], leader['exe'])] = leader
            write_new(args.session + '/started.py', repr({'owner': identity(os.getpid()), 'browser': leader}) + '\n')
            # The detached guardian owns this deadline; the ADB client can exit.
            deadline = time.monotonic() + args.seconds + 3
            while child.poll() is None:
                track_descendants(args.candidate, leader, tracked, args.uid)
                if requested[0] or stop_requested(args.session):
                    result['stop_requested'] = True
                    break
                if time.monotonic() >= deadline:
                    result['timed_out'] = True
                    break
                time.sleep(0.1)
    except Exception as exc:
        # Do not include a traceback, command line, environment or arbitrary
        # exception text; only stable error type and our bounded known messages.
        result['error_type'] = type(exc).__name__
        if isinstance(exc, ValueError):
            result['error'] = str(exc)
        if isinstance(exc, OSError):
            result['errno'] = exc.errno
    finally:
        if connection is not None:
            connection.close()
        for descriptor in (birth_read, birth_write):
            if descriptor is not None:
                os.close(descriptor)
        try:
            cleanup_group(args.candidate, leader, child, result)
        except Exception as exc:
            result['cleanup_error_type'] = type(exc).__name__
        try:
            cleanup_detached(args.candidate, leader, child, args.uid, tracked, result)
            if leader is not None:
                result['remaining_group'] = checked_group(args.candidate, leader)
        except Exception as exc:
            result['detached_cleanup_error_type'] = type(exc).__name__
        if child is not None:
            result['browser_exit'] = child.poll()
        try:
            result['after'] = stock_snapshot()
            result['stock_unchanged'] = before is not None and same_stock(before, result['after']) and same_stock(baseline, result['after'])
        except Exception as exc:
            result['stock_unchanged'] = False
            result['snapshot_error_type'] = type(exc).__name__
        try:
            result['remaining_private_processes'] = private_processes(args.candidate)
        except Exception as exc:
            result['private_process_error_type'] = type(exc).__name__
        result['observed_owned_processes'] = [tracked[key] for key in sorted(tracked)]
        if lease is not None and result.get('remaining_private_processes') == [] and result.get('remaining_group', []) == []:
            try:
                release_lease(lease, lease_owner)
                result['candidate_lease_released'] = True
            except Exception as exc:
                result['lease_release_error_type'] = type(exc).__name__
        elif lease is not None:
            result['candidate_lease_retained'] = True
        result['finished_epoch'] = time.time()
        result['own_group_closed'] = leader is not None and result.get('remaining_group') == []
        result['passed'] = (result.get('stock_unchanged') is True and
                            result.get('remaining_private_processes') == [] and
                            result['own_group_closed'] and result['browser_exit'] == 0 and
                            not result['timed_out'] and not result['stop_requested'] and
                            not any(key in result for key in ('error_type', 'cleanup_error_type', 'detached_cleanup_error_type', 'snapshot_error_type', 'private_process_error_type', 'lease_release_error_type')))
        result['lifecycle_passed'] = result['passed']
        result['page_passed'] = None  # HOST separately checks fixture events and the window PNG.
        write_new(result_path, J.dumps(result, indent=2, sort_keys=True) + '\n')
        write_new(args.session + '/result.py', repr(result) + '\n')
        write_new(args.session + '/COMPLETE', '')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
