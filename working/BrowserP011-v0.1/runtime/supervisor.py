# -*- coding: utf-8 -*-
"""Launch a detached, bounded browser guardian and wait for its explicit result.

Control directory and baseline remain owned by the supervisor. Only session/app
is writable by the browser uid. No vendor process is signalled.
"""
import os
import subprocess
import sys
import time

from guardian import arguments
from safety import (identity, load_baseline, read_literal, same_stock,
                    stock_snapshot, validate_app_directory, validate_paths,
                    write_new)


def main():
    args = arguments()
    validate_paths(args.candidate, args.session)
    baseline = load_baseline(args.baseline, args.session)
    validate_app_directory(args.session, args.uid, args.gid)
    if not same_stock(baseline, stock_snapshot()):
        raise ValueError('Stock changed before guardian launch')
    for name in ('guardian-owner.py', 'result.py', 'result.json', 'STOP', 'COMPLETE'):
        if os.path.lexists(args.session + '/' + name):
            raise ValueError('Session was already used or stop was requested')
    write_new(args.session + '/supervisor-owner.py', repr(identity(os.getpid())) + '\n')
    guardian = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'guardian.py')
    command = [sys.executable, '-B', guardian, '--candidate', args.candidate,
               '--session', args.session, '--baseline', args.baseline,
               '--seconds', str(args.seconds), '--uid', str(args.uid), '--gid', str(args.gid),
               '--shell-integration', args.shell_integration]
    if args.offline_no_sandbox:
        command.append('--offline-no-sandbox')
    if args.public_site is not None:
        command.extend(['--public-site', args.public_site, '--public-no-sandbox'])
    if args.interactive:
        command.extend(['--interactive', '--interactive-no-sandbox'])
    with open(args.session + '/guardian.stdout.raw', 'xb') as stdout, open(args.session + '/guardian.stderr.raw', 'xb') as stderr:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                 stderr=stderr, start_new_session=True, close_fds=True)
    write_new(args.session + '/guardian-launch.py', repr(identity(child.pid)) + '\n')
    result_path = args.session + '/result.py'
    deadline = time.monotonic() + args.seconds + 30
    while time.monotonic() < deadline:
        if os.path.isfile(args.session + '/COMPLETE'):
            result = read_literal(result_path, maximum=262144)
            if not isinstance(result, dict) or result.get('schema') != 'p011.browser.runtime-result.v1' or result.get('session') != args.session:
                raise ValueError('Invalid guardian result')
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise ValueError('Guardian result exists but guardian exit unconfirmed')
            print('RESULT=' + repr({'passed': result.get('passed') is True,
                                   'lifecycle_passed': result.get('lifecycle_passed') is True,
                                   'page_passed': None,
                                   'guardian_exit': child.returncode,
                                   'browser_exit': result.get('browser_exit'),
                                   'stock_unchanged': result.get('stock_unchanged'),
                                   'own_group_closed': result.get('own_group_closed'),
                                   'result_path': args.session + '/result.json'}))
            return 0 if result.get('passed') is True and child.returncode == 0 else 1
        if child.poll() is not None:
            raise ValueError('Guardian exited without an explicit result')
        time.sleep(0.1)
    # The detached guardian retains responsibility; a host timeout never claims
    # the browser closed and never signals an unverified PID.
    print('RESULT=' + repr({'passed': False, 'guardian_completion_unconfirmed': True,
                           'result_path': args.session + '/result.json'}))
    return 2


if __name__ == '__main__':
    sys.exit(main())
