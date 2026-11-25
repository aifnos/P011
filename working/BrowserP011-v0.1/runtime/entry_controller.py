# -*- coding: utf-8 -*-
"""Fixed native settings entry; never accepts a URL, command or process ID.

Python 3.5 compatible. The native root QML reads a private endpoint token;
web content has neither that token nor access to a shell/WebChannel bridge.
"""
import argparse
import fcntl
import hmac
import os
import re
import signal
import stat
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import p011_json as J
from safety import (AREA, HASH_PATHS, canonical_identity, control_directory, digest, identity,
                    private_processes, read_literal, same_stock, stock_snapshot,
                    validate_paths, write_new)

SETTINGS = AREA + '/settings'
CONFIG = SETTINGS + '/entry-config.py'
ENDPOINT = SETTINGS + '/endpoint.json'


def private_regular(path, maximum=1048576):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
        raise ValueError('Unsafe private settings control file')
    return info


def random_hex(count):
    import binascii
    return binascii.hexlify(os.urandom(count)).decode('ascii')


def atomic_private(path, content):
    if os.path.lexists(path):
        private_regular(path)
    temporary = path + '.new-' + random_hex(8)
    write_new(temporary, content)
    os.rename(temporary, path)


def current_boot():
    with open('/proc/sys/kernel/random/boot_id') as handle:
        return handle.read(64).strip()


def verified_config():
    control_directory(SETTINGS)
    private_regular(CONFIG)
    config = read_literal(CONFIG)
    if (not isinstance(config, dict) or config.get('schema') != 'p011.browser.entry-config.v1'
            or config.get('interactive_no_sandbox') is not True):
        raise ValueError('Explicit interactive installation configuration required')
    candidate = config.get('candidate', '')
    if not re.fullmatch(re.escape(AREA) + r'/candidates/browser-685-[a-f0-9]{16,64}', candidate):
        raise ValueError('Invalid installed candidate')
    control_directory(candidate)
    expected = config.get('hashes')
    if (not isinstance(expected, dict) or set(expected) != set(HASH_PATHS)
            or any(not isinstance(v, str) or not re.fullmatch(r'[a-f0-9]{64}', v) for v in expected.values())):
        raise ValueError('Exact installed stock identities required')
    checksum = config.get('manifest_literal_sha256', '')
    if not isinstance(checksum, str) or not re.fullmatch(r'[a-f0-9]{64}', checksum):
        raise ValueError('Installed manifest identity required')
    manifest_path = candidate + '/.candidate-manifest.py'
    private_regular(manifest_path, 4194304)
    private_regular(candidate + '/.candidate-complete', 0)
    if digest(manifest_path) != checksum:
        raise ValueError('Installed manifest differs')
    stored = read_literal(manifest_path, maximum=4194304)
    rows = stored['manifest']['files']
    seen = set()
    for row in rows:
        relative = row['path']
        if (not isinstance(relative, str) or relative.startswith('/') or '\\' in relative
                or any(part in ('', '.', '..') for part in relative.split('/'))):
            raise ValueError('Invalid manifest path')
        path = candidate + '/' + relative
        control_directory(os.path.dirname(path))
        info = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != row['mode'] or info.st_size != row['size']
                or digest(path) != row['sha256'] or relative in seen):
            raise ValueError('Installed candidate integrity differs')
        seen.add(relative)
    if not {'bin/p011-browser-probe', 'libexec/QtWebEngineProcess', 'runtime/supervisor.py'}.issubset(seen):
        raise ValueError('Incomplete installed browser')
    if stock_snapshot()['hashes'] != expected:
        raise ValueError('Current stock differs from settings installation')
    if os.path.realpath(__file__) != candidate + '/runtime/entry_controller.py':
        raise ValueError('Controller must run from the installed candidate')
    return config


class Entry:
    def __init__(self, config):
        self.config = config
        self.candidate = config['candidate']
        self.child = None
        self.session = None
        self.state = 'ready'
        self.reason = None
        self.baseline = None
        self.last_native_ui = None

    def native_ui_unchanged(self):
        try:
            if self.baseline['boot_id'] != current_boot():
                return False
            for expected in self.baseline['processes']:
                if expected['name'] not in ('Z03', 'control_engine', 'weston'):
                    continue
                if canonical_identity(identity(expected['pid'])) != canonical_identity(expected):
                    return False
                parent = expected.get('parent_identity')
                if parent and canonical_identity(identity(parent['pid'])) != canonical_identity(parent):
                    return False
            return True
        except (OSError, ValueError, IndexError, KeyError):
            return False

    def request_close(self):
        # The detached guardian can outlive its supervisor. Session ownership,
        # rather than a live Popen handle, keeps the STOP path available.
        if self.session is not None and not os.path.lexists(self.session + '/COMPLETE'):
            stop = self.session + '/STOP'
            if not os.path.lexists(stop):
                write_new(stop, '')

    def poll(self):
        if self.child is not None:
            code = self.child.poll()
            if code is None:
                self.state = 'running' if os.path.isfile(self.session + '/started.py') else 'starting'
                if (self.last_native_ui is None or time.monotonic() - self.last_native_ui > 15
                        or not self.native_ui_unchanged()):
                    self.request_close()
            else:
                complete = self.session + '/COMPLETE'
                if not os.path.isfile(complete):
                    self.state, self.reason = 'error', 'completion_unconfirmed'
                    self.request_close()
                else:
                    result = read_literal(self.session + '/result.py', maximum=262144)
                    if result.get('session') != self.session or result.get('candidate') != self.candidate:
                        raise ValueError('Completed settings session binding differs')
                    closed = (result.get('remaining_private_processes') == []
                              and result.get('remaining_group') == []
                              and result.get('stock_unchanged') is True)
                    self.state = 'stopped' if closed else 'error'
                    self.reason = None if closed else 'cleanup_unconfirmed'
                self.child = None
        elif self.session is not None:
            complete = self.session + '/COMPLETE'
            if os.path.isfile(complete):
                result = read_literal(self.session + '/result.py', maximum=262144)
                if result.get('session') != self.session or result.get('candidate') != self.candidate:
                    raise ValueError('Completed settings session binding differs')
                closed = (result.get('remaining_private_processes') == []
                          and result.get('remaining_group') == []
                          and result.get('stock_unchanged') is True)
                self.state = 'stopped' if closed else 'error'
                self.reason = None if closed else 'cleanup_unconfirmed'
            else:
                self.request_close()
        return self.state

    def response(self):
        self.poll()
        result = {'ok': self.state != 'error', 'state': self.state}
        if self.reason:
            result['reason'] = self.reason
        return result

    def open(self):
        self.poll()
        if self.child is not None:
            return self.response()
        if self.state == 'error':
            return self.response()
        baseline = stock_snapshot()
        if baseline['hashes'] != self.config['hashes']:
            raise ValueError('stock_changed')
        if private_processes(self.candidate):
            raise ValueError('browser_busy')
        space = os.statvfs(AREA)
        if space.f_bavail * space.f_frsize < 128 * 1024 * 1024:
            raise ValueError('storage_low')
        session = AREA + '/sessions/' + time.strftime('%Y%m%d-%H%M%S') + '-' + random_hex(4)
        os.mkdir(session, 0o755)
        os.chmod(session, 0o755)
        validate_paths(self.candidate, session)
        for suffix in ('app', 'app/tmp', 'app/cache', 'app/config', 'app/data', 'app/runtime'):
            path = session + '/' + suffix
            os.mkdir(path, 0o700)
            os.chown(path, 65534, 44)
            os.chmod(path, 0o700)
        write_new(session + '/baseline.py', repr(baseline) + '\n')
        write_new(session + '/entry-mode.py', repr({
            'schema': 'p011.browser.settings-session.v1', 'interactive': True,
            'interactive_no_sandbox': True, 'seconds': 1800, 'uid': 65534, 'gid': 44,
            'candidate': self.candidate, 'session': session}) + '\n')
        if not same_stock(baseline, stock_snapshot()):
            raise ValueError('stock_changed')
        command = [sys.executable, '-B', self.candidate + '/runtime/supervisor.py',
                   '--candidate', self.candidate, '--session', session,
                   '--baseline', session + '/baseline.py', '--seconds', '1800',
                   '--uid', '65534', '--gid', '44', '--shell-integration', 'wl-shell',
                   '--interactive', '--interactive-no-sandbox']
        with open(session + '/supervisor.stdout.raw', 'xb') as stdout, open(session + '/supervisor.stderr.raw', 'xb') as stderr:
            self.child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                          stdout=stdout, stderr=stderr, close_fds=True,
                                          start_new_session=True)
        self.session = session
        self.baseline = baseline
        self.last_native_ui = time.monotonic()
        write_new(session + '/entry-launch.py', repr(identity(self.child.pid)) + '\n')
        self.state, self.reason = 'starting', None
        return self.response()

    def close(self):
        self.poll()
        self.request_close()
        return self.response()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *args):
        pass  # Never log endpoint tokens, headers or user-supplied request lines.

    def reply(self, value, code=200):
        content = J.dumps(value).encode('ascii')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(content)

    def setup(self):
        super(Handler, self).setup()
        self.connection.settimeout(2)

    def do_POST(self):
        headers = self.headers
        supplied_token = headers.get('X-P011-Browser-Token', '')
        authorized = (self.client_address[0] == '127.0.0.1'
                      and headers.get('Host') == self.server.exact_host
                      and len(headers.get_all('Host', [])) == 1
                      and headers.get('Origin') is None
                      and headers.get('Transfer-Encoding') is None
                      and headers.get('Content-Length', '0') == '0'
                      and headers.get('X-P011-Native-UI') == 'browser-qml-runtime'
                      and len(headers.get_all('X-P011-Native-UI', [])) == 1
                      and len(headers.get_all('X-P011-Browser-Token', [])) == 1
                      and re.fullmatch(r'[a-f0-9]{64}', supplied_token) is not None
                      and hmac.compare_digest(supplied_token, self.server.token))
        if not authorized:
            self.reply({'ok': False, 'state': 'error', 'reason': 'request_rejected'}, 403)
            return
        try:
            if self.path == '/open':
                self.server.entry.last_native_ui = time.monotonic()
                result = self.server.entry.open()
            elif self.path == '/status':
                self.server.entry.last_native_ui = time.monotonic()
                result = self.server.entry.response()
            elif self.path == '/close':
                result = self.server.entry.close()
            else:
                self.reply({'ok': False, 'state': 'error', 'reason': 'route_rejected'}, 404)
                return
            self.reply(result)
        except Exception as exc:
            known = str(exc) if isinstance(exc, ValueError) else ''
            reason = known if known in ('stock_changed', 'browser_busy', 'storage_low') else 'launch_failed'
            self.reply({'ok': False, 'state': 'error', 'reason': reason}, 409)

    def do_GET(self):
        self.reply({'ok': False, 'state': 'error', 'reason': 'method_rejected'}, 405)


def service_identity():
    path = SETTINGS + '/entry-owner.py'
    try:
        private_regular(path)
    except OSError as exc:
        if exc.errno == 2:
            return None
        raise
    owner = read_literal(path)
    if (owner.get('schema') != 'p011.browser.entry-owner.v1'
            or owner.get('controller_source') != os.path.realpath(__file__)
            or owner.get('controller_sha256') != digest(__file__)):
        raise ValueError('Controller owner binding differs')
    if owner.get('boot_id') != current_boot():
        return None
    try:
        current = identity(owner['identity']['pid'])
        uid = os.stat('/proc/' + str(current['pid'])).st_uid
        with open('/proc/' + str(current['pid']) + '/stat') as handle:
            raw = handle.read(8192)
        if raw[raw.rindex(')') + 2:].split()[0] == 'Z':
            return None
    except OSError as exc:
        if exc.errno in (2, 3):
            return None
        raise
    if canonical_identity(current) != canonical_identity(owner['identity']) or uid != 0:
        return None
    return current


def service_control(stop=False):
    control_directory(SETTINGS)
    owner = service_identity()
    if stop and owner is not None:
        # Identity is rechecked immediately before signalling only this service.
        if canonical_identity(identity(owner['pid'])) != canonical_identity(owner):
            raise ValueError('Controller identity changed before stop')
        os.kill(owner['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and service_identity() is not None:
            time.sleep(0.1)
        owner = service_identity()
    print('RESULT=' + repr({'schema': 'p011.browser.entry-service.v1',
                            'running': owner is not None, 'stop_requested': stop,
                            'stopped': owner is None,
                            'stopped_scope': 'controller_process_only'}))
    return 0 if (owner is None if stop else owner is not None) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=CONFIG, choices=(CONFIG,))
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--stop', action='store_true')
    action.add_argument('--status', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Root settings controller required')
    os.umask(0o077)
    if args.stop or args.status:
        return service_control(args.stop)
    control_directory(SETTINGS)
    lock_path = SETTINGS + '/entry.lock'
    if os.path.lexists(lock_path):
        private_regular(lock_path, 0)
    lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    config = verified_config()
    entry = Entry(config)
    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.timeout = 0.5
    server.entry = entry
    server.token = random_hex(32)
    server.exact_host = '127.0.0.1:' + str(server.server_address[1])
    endpoint = J.dumps({'schema': 'p011.browser.endpoint.v1', 'host': '127.0.0.1',
                        'port': server.server_address[1], 'token': server.token}) + '\n'
    atomic_private(ENDPOINT, endpoint)
    endpoint_sha = digest(ENDPOINT)
    owner = {'schema': 'p011.browser.entry-owner.v1', 'boot_id': current_boot(),
             'identity': identity(os.getpid()), 'candidate': config['candidate'],
             'controller_source': os.path.realpath(__file__),
             'controller_sha256': digest(__file__), 'endpoint_sha256': endpoint_sha}
    atomic_private(SETTINGS + '/entry-owner.py', repr(owner) + '\n')
    stopped = [False]
    def stop(signum, frame):
        stopped[0] = True
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, stop)
    try:
        while not stopped[0]:
            server.handle_request()
            entry.poll()
    finally:
        server.server_close()
        entry.close()
        deadline = time.monotonic() + 25
        while (entry.child is not None or (entry.session is not None
                and not os.path.isfile(entry.session + '/COMPLETE'))) and time.monotonic() < deadline:
            entry.poll()
            time.sleep(0.1)
        if os.path.isfile(ENDPOINT) and digest(ENDPOINT) == endpoint_sha:
            os.unlink(ENDPOINT)
        os.close(lock)
    return 0


if __name__ == '__main__':
    sys.exit(main())
