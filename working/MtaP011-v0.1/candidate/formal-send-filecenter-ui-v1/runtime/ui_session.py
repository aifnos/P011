"""Fixed sender/FileCenter UI composition, not a deployed entry.

The real v2 sender is retained before its constructor, uses the parent's one
600-second window, and creates its own Companion once. No second Companion,
receiver Owner, automatic RF action, bootstrap or synthetic guardian exists.
The selected original guardian is separately pinned in ui_guardian.py.

The sender QML sources exist, but no sender ELF/asset validator has been built
or sealed. run_fixed therefore refuses BEFORE constructing a window or doing
device IO. _run_prepared is the actual fixed production wiring for that later
seal, not a HOST model or fabricated invocation receipt. The current v2
Companion waits do not yet consume the parent's absolute cleanup deadline;
that gap remains explicit until the separately versioned deadline graph lands.
"""
import errno
import hashlib
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types

SENDER_PIN = (24059, '5408b6d72812a46e84d6937263153420e0791313141919bdba949a3eec248b9e')
GUARDIAN_PIN = (43991, '27bb19a168a1ba85001a53a213acbb25f83d9d962ffba4d6ef20b99138a013d9')
SENDER_ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v2'
SENDER_PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v2'
PROFILE = 'send-interactive-v1'
SESSION = 'b6a84fe755092535bb996f40'
ASSETS = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-send-filecenter-ui-v1'
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
STOCK_PINS = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
)
# No future SHA, successful stage projection or mutable admission flag.
# The later actual builder/validator must replace this refusal with real pins.
SENDER_ASSET_SEAL = None
_RETAINED = None


class SenderUiError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _need(value, code):
    if not value:
        raise SenderUiError(code)


def _meta(value):
    row = tuple(getattr(value, key) for key in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    _need(all(type(item) is int and item >= 0 for item in row), 'metadata_unknown')
    return row


def _definitions(raw, pin, name):
    _need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == pin,
          'source_pin')
    module = types.ModuleType(name)
    module.__file__ = '<fixed-sender-ui/' + name + '>'
    exec(raw, module.__dict__)
    return module


class _UiScope(object):
    """Actual UI FD/stock lifetime only; no State, Gate or Native authority."""
    def __init__(self, sender_module, guardian_module):
        _need(sys.platform == 'linux' and os.geteuid() == 0 and
              os.uname()[4] == 'armv7l' and os.O_NOFOLLOW == 0x8000 and
              os.O_CLOEXEC == 0x80000 and threading.active_count() == 1,
              'unsupported_platform')
        self.sender_module, self.guardian_module = sender_module, guardian_module
        self.worker, self.pid, self.clock = threading.current_thread(), os.getpid(), time.monotonic
        self.started_at = self.last = self.clock()
        _need(type(self.started_at) is float and math.isfinite(self.started_at), 'clock_unknown')
        self.until = self.started_at + 600.0
        self.cleanup_until = self.until + 60.0
        self.window = self._window_original = (self.started_at, self.until, self.cleanup_until)
        self.rows, self.failures = [], []
        self.sender = self.sender_ticket = self.filecenter = self.filecenter_ticket = None
        self.channel = self.guardian = self.ui = self.candidate = None
        self.credentials_row = None
        self.stopped = self._stopped_original = [False]
        self.closing = False

    @property
    def owner(self):
        return None if self.sender is None else self.sender.owner

    def check(self, cleanup=False):
        _need(self.window is self._window_original and self.started_at is self.window[0] and
              self.until is self.window[1] and self.cleanup_until is self.window[2] and
              self.cleanup_until == self.until + 60.0 and
              self.clock is time.monotonic and self.worker is threading.current_thread() and
              self.pid == os.getpid(), 'window_changed')
        _need(self.stopped is self._stopped_original and type(self.stopped) is list and
              len(self.stopped) == 1 and type(self.stopped[0]) is bool,
              'stop_container_changed')
        now = self.clock()
        _need(type(now) is float and math.isfinite(now) and now >= self.last, 'clock_unknown')
        self.last = now
        _need(now < (self.cleanup_until if cleanup else self.until) and
              (cleanup or (not self.closing and not self.stopped[0])), 'deadline')
        if self.sender is not None and self.sender_ticket['constructed']:
            _need(self.sender_module.FixedSendSession.window_current(self.sender) and
                  self.sender.parent_until is self.until and
                  self.sender.parent_cleanup_until is self.cleanup_until and
                  self.sender.until is self.until, 'sender_window_changed')
        return now

    def mark_closing(self):
        # The guardian consumes this retained bool container, not a callback.
        # Mutate the original even if a public alias was replaced; do not renew
        # either activity or cleanup deadlines while refusing new audio.
        self.closing = True
        self._stopped_original[0] = True

    def _row(self, fd):
        row = dict(fd=fd, original_fd=fd, metadata=None, unknown=True, closed=False,
                   attempted=False, no_fd=False, error=None)
        self.rows.append(row)
        collisions = [old for old in self.rows if old is not row and
                      old['fd'] == fd and not old['closed']]
        if collisions:
            for old in collisions: old['unknown'] = True
            raise SenderUiError('fd_collision')
        _need(type(fd) is int and fd > 2, 'fd_unknown')
        row['metadata'] = _meta(os.fstat(fd))
        row['unknown'] = False
        return row

    def open_fd(self, path, flags, mode=0o400, parent=None):
        self.check()
        return self._row(os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                               **({} if parent is None else {'dir_fd': parent})))

    def close_fd(self, row):
        _need(any(row is original for original in self.rows), 'foreign_fd')
        if row['attempted']: return row['closed'] and not row['unknown']
        row['attempted'] = True
        try:
            _need(not row['unknown'] and row['fd'] is row['original_fd'] and
                  _meta(os.fstat(row['fd']))[:5] == row['metadata'][:5], 'fd_changed')
            returned = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['closed'] = returned is None and error.errno == errno.EBADF
            _need(row['closed'], 'fd_close_unknown')
        except BaseException as error:
            row['error'], row['unknown'] = error, True
            self.failures.append(error)
        return row['closed'] and not row['unknown']

    def raw_file(self, parent, name, raw=b''):
        _need(type(raw) is bytes and len(raw) <= 1048576, 'private_log_limit')
        row = self.open_fd(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, parent)
        if raw:
            _need(os.write(row['fd'], raw) == len(raw), 'private_log_write')
            os.fsync(row['fd'])
        return row


def _start_sender(scope, source_rows):
    """Real v2 Boot/Owner producer, with partial original retained first."""
    scope.check()
    module, creator = scope.sender_module, scope.sender_module.FixedSendSession
    _need(scope.sender is None and module.ROOT == SENDER_ROOT and
          module.PHYSICAL_ROOT == SENDER_PHYSICAL_ROOT, 'sender_source')
    ticket = dict(creator=creator, original=None, constructed=False,
                  started=False, start_return=None, failure=None, close_return=None)
    scope.sender_ticket = ticket
    scope.sender = ticket['original'] = object.__new__(creator)
    try:
        creator.__init__(scope.sender, scope.until, scope.cleanup_until, True, PROFILE)
        ticket['constructed'] = True
        scope.check()
        ticket['start_return'] = creator.start(scope.sender)
        _need(ticket['start_return'] is scope.sender, 'sender_start_return')
        ticket['started'] = True
        owner = scope.sender.owner
        _need(owner is scope.sender.owner_ticket['partial'] and
              type(owner) is scope.sender.owner_module.FixedStateServiceOwner and
              owner.until is scope.until and owner.worker is scope.worker and
              owner._startup_namespace_original is scope.sender.owner_module.__dict__,
              'sender_owner_changed')
        # Only this real Owner loads the nine sources and invokes its original
        # retainer. There is deliberately no UI-side Companion/create fallback.
        try:
            scope.filecenter = owner.create_filecenter(source_rows)
        finally:
            scope.filecenter_ticket = owner.filecenter_ticket
        ticket_fc = scope.filecenter_ticket
        _need(ticket_fc is owner._filecenter_ticket_original and
              ticket_fc['original'] is scope.filecenter and ticket_fc['create_returned'] and
              owner._filecenter_current(), 'filecenter_original')
        scope.channel.bind(scope.filecenter.audio, ticket_fc['modules'][6]['module'], scope.filecenter)
        _need(scope.channel.current() and owner._filecenter_current(), 'audio_guardian_source')
        endpoint = creator.credentials(scope.sender)
        toolbox = ticket_fc['methods']['credentials'](scope.filecenter)
        for pair in (endpoint, toolbox):
            _need(type(pair) is dict and set(pair) == {'endpoint', 'token'} and
                  re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', pair['endpoint']) and
                  1 <= int(pair['endpoint'].rsplit(':', 1)[1]) <= 65535 and
                  re.fullmatch('[0-9a-f]{64}', pair['token']), 'credential_pair')
        _need(endpoint['endpoint'] != toolbox['endpoint'] and endpoint['token'] != toolbox['token'],
              'credential_pair')
        return endpoint, toolbox
    except BaseException as error:
        ticket['failure'] = error
        scope.failures.append(error)
        raise


def _close_sender(scope):
    """Known originals close even late; no Owner/RF success is projected."""
    scope.mark_closing()
    if scope.channel is not None and scope.channel.bound:
        try: scope.channel.prevent_new()
        except BaseException as error: scope.failures.append(error)
    if scope.sender_ticket is None:
        return True
    ticket = scope.sender_ticket
    if not ticket['constructed']:
        return False  # Preserve partial ctor; do not invoke methods on guesses.
    try:
        # Actual Owner closes its one Companion before State/HTTP/directories.
        # Current v2 close has bounded local waits, not the future absolute-
        # deadline FileCenter contract. Do not label this parent-deadline PASS.
        ticket['close_return'] = ticket['creator'].close(scope.sender)
        return (ticket['close_return'] is True and ticket['creator']._closed(scope.sender) and
                (scope.filecenter_ticket is None or scope.sender.owner._filecenter_closed()) and
                (scope.channel is None or not scope.channel.bound or scope.channel.settled()))
    except BaseException as error:
        scope.failures.append(error)
        return False


def _stock(scope):
    helper = scope.guardian_module
    tracked = helper._scan(names=(b'Z03', b'control_engine', b'weston'))
    _need(all(sum(row['comm'] == name for row in tracked) == 1 for name in
              (b'Z03', b'control_engine', b'weston')), 'stock_topology')
    original = next(row for row in tracked if row['comm'] == b'Z03')
    _need(original['exe'] == '/usr/bin/Z03' and
          original['args'][1:] == ('-platform', 'wayland'), 'stock_ui')
    launcher = helper._proc(original['parent'])
    _need(helper._alive(launcher) and '/usr/bin/zyb_z03_launch.sh' in launcher['args'][:3] and
          launcher['state'] not in ('T', 't', 'D'), 'stock_launcher')
    rows = tuple((path, _meta(value) + (value.st_mtime_ns, value.st_ctime_ns))
        for path, value in ((path, os.stat(path, follow_symlinks=False)) for path, sha in STOCK_PINS))
    _need(tuple((path, helper._hash(path, 8388608, meta)) for path, meta in rows) == STOCK_PINS,
          'stock_pins')
    environment = dict(os.fsdecode(part).split('=', 1) for part in
        helper._read('/proc/%d/environ' % original['pid'], 131072).split(b'\0') if b'=' in part)
    _need(environment.get('XDG_RUNTIME_DIR') == '/run/user/0' and
          environment.get('WAYLAND_DISPLAY', 'wayland-0') == 'wayland-0' and
          stat.S_ISSOCK(os.stat('/run/user/0/wayland-0').st_mode), 'wayland')
    return dict(boot=helper._boot(), original=original, launcher=launcher,
                tracked=tracked, pins=STOCK_PINS, stock_metadata=rows), environment,


def _run_prepared(sender_module, helper, source_rows, assets):
    """Actual sender-only choreography; caller must have sealed real assets."""
    global _RETAINED
    _need(not any(name.startswith(('mta_', 'p011_')) for name in sys.modules), 'namespace_busy')
    scope = _UiScope(sender_module, helper)
    _RETAINED = scope  # Strong original before any IO/constructor/fork.
    facts = dict(complete=False, ui_ready=False, credentials_removed=False,
                 original_ui_exited=False, candidate_exited=False,
                 owner_closed=False, guardian_exited=False, stock_restored=False,
                 worker_fds_closed=False, resource_pending=True,
                 automatic_rf_action=False, receive_worker_started=False,
                 filecenter_parent_deadline_verified=False, reason='not_started')
    guard_pid = None
    baseline = candidate = control = write_row = read_row = None
    credentials_meta = None
    try:
        scope.check()
        asset_facts = assets.validate_assets(scope.until)
        for path in ('/mnt/data/p011-toolbox/native.lock', '/mnt/data/p011-toolbox/bili-awake.lock',
                     '/tmp/p011-menutest.lock', '/mnt/data/p011-menu'):
            _need(not os.path.lexists(path), 'other_ui_trial')
        baseline, environment = _stock(scope)
        cwd = os.readlink('/proc/%d/cwd' % baseline['original']['pid'])
        helper._no_core()
        anchor = scope.open_fd('/var/volatile/tmp', os.O_RDONLY | os.O_DIRECTORY)
        _need(anchor['metadata'][2:5] == (stat.S_IFDIR | 0o1777, 0, 0), 'unsafe_control_anchor')
        os.mkdir(CONTROL_NAME, 0o700, dir_fd=anchor['fd'])
        control = scope.open_fd(CONTROL_NAME, os.O_RDONLY | os.O_DIRECTORY, parent=anchor['fd'])
        _need(control['metadata'][2:5] == (stat.S_IFDIR | 0o700, 0, 0), 'unsafe_control')
        baseline['control_meta'] = control['metadata'][:5]
        logs = tuple(scope.raw_file(control['fd'], name) for name in
                     ('guardian.stdout.raw', 'guardian.stderr.raw'))
        ui_logs = tuple(scope.raw_file(control['fd'], name) for name in
                        ('candidate.stdout.raw', 'candidate.stderr.raw'))
        to_guard = tuple(scope._row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        from_guard = tuple(scope._row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        worker = helper._proc(os.getpid())
        _need(scope.owner is None and threading.active_count() == 1, 'fork_boundary')
        sys.stdout.flush(); sys.stderr.flush()
        guard_pid = os.fork()
        if guard_pid == 0:
            helper._guardian(scope, to_guard[0]['fd'], from_guard[1]['fd'], logs, baseline, worker)
            os._exit(3)
        scope.guardian = helper._proc(guard_pid)
        write_row, read_row = to_guard[1], from_guard[0]
        for row in (to_guard[0], from_guard[1]) + logs:
            _need(scope.close_fd(row), 'guardian_parent_fd_close')
        pending, armed, arm_until = b'', False, min(scope.until, time.monotonic()+5.0)
        while time.monotonic() < arm_until:
            scope.check()
            pending, frames, eof = helper._pipe_read(read_row['fd'], pending)
            _need(not eof and all(frame == 'ARMED' for frame in frames), 'guardian_not_armed')
            if frames:
                _need(len(frames) == 1, 'guardian_armed_frame'); armed = True; break
            time.sleep(.05)
        _need(armed, 'guardian_not_armed')
        scope.channel = helper._FileCenterGuardianChannel(scope, write_row, read_row, pending,
            baseline, worker, scope.guardian, scope._stopped_original)
        endpoint, toolbox = _start_sender(scope, source_rows)
        # No full-path reopen after validation: keep the actual parent/child
        # FD chain, using the validator's original credential-only bindings.
        parent, asset_edges = None, []
        for name, metadata in asset_facts['credential_directory_bindings']:
            row = scope.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent)
            _need(row['metadata'][:5] == metadata, 'asset_directory_changed')
            asset_edges.append((parent,name,row)); parent = row['fd']
        _need(asset_edges and asset_edges[-1][1] == SESSION, 'asset_directory_changed')
        area = asset_edges[-1][2]
        credentials = scope.raw_file(area['fd'], 'credentials.json')
        scope.credentials_row = credentials
        codec = scope.filecenter_ticket['modules'][0]['module']
        private = codec.dumps(dict(session=SESSION, endpoint=endpoint['endpoint'], token=endpoint['token'],
            toolboxEndpoint=toolbox['endpoint'], toolboxToken=toolbox['token'])).encode('utf-8')
        _need(len(private) <= 1024 and os.write(credentials['fd'], private) == len(private), 'credential_write')
        os.fsync(credentials['fd']); credentials_meta = _meta(os.fstat(credentials['fd']))
        _need(scope.close_fd(credentials), 'credential_close')
        endpoint = toolbox = private = None
        helper._signal(baseline['launcher'], signal.SIGSTOP, baseline['boot'])
        stopped_until = min(scope.until, time.monotonic()+2.0)
        while time.monotonic() < stopped_until and helper._refresh(baseline['launcher'])['state'] not in ('T','t'):
            time.sleep(.05)
        _need(helper._refresh(baseline['launcher'])['state'] in ('T','t'), 'launcher_not_stopped')
        helper._terminate(baseline['original'], baseline['boot'])
        facts['original_ui_exited'] = True
        scope.check()
        environment = dict(environment, QML_DISABLE_DISK_CACHE='1', QT_LOGGING_TO_CONSOLE='1')
        environment.pop('QML_FORCE_DISK_CACHE', None)
        with open(os.devnull, 'rb') as input_stream:
            scope.ui = subprocess.Popen([helper.CANDIDATE,'-platform','wayland'], stdin=input_stream,
                stdout=ui_logs[0]['fd'], stderr=ui_logs[1]['fd'], env=environment, cwd=cwd,
                close_fds=True, start_new_session=True)
        candidate_until = min(scope.until,time.monotonic()+2.0)
        while time.monotonic()<candidate_until:
            candidate = scope.candidate = helper._proc(scope.ui.pid)
            if helper._alive(candidate) and candidate['exe'] == helper.CANDIDATE and candidate['parent'] == scope.pid:
                break
            _need(scope.ui.poll() is None, 'candidate_start'); time.sleep(.02)
        _need(helper._alive(candidate) and candidate['exe'] == helper.CANDIDATE and
              candidate['parent'] == scope.pid and candidate['sid'] == candidate['pid'], 'candidate_start')
        helper._pipe_write(write_row['fd'], 'CAND %d %s\n' % (candidate['pid'],candidate['start']))
        readers = tuple(scope.open_fd(name, os.O_RDONLY, parent=control['fd']) for name in
                        ('candidate.stdout.raw','candidate.stderr.raw'))
        for row in ui_logs: _need(scope.close_fd(row), 'ui_writer_close')
        launched, tails = time.monotonic(), [b'',b'']
        while time.monotonic() < scope.until-1.0:
            scope.check()
            _need(scope.owner.start_complete and scope.owner.thread.is_alive() and
                  scope.owner._filecenter_current() and scope.channel.current(), 'sender_original_changed')
            _need(helper._alive(helper._refresh(scope.guardian)), 'guardian_missing')
            leave = False
            for index, row in enumerate(readers):
                _need(os.fstat(row['fd']).st_size <= 4194304, 'ui_log_budget')
                data = tails[index]+os.read(row['fd'],65536)
                _need(b'FORMAL_UI_FAILED' not in data and b'FORMAL_SCENE_FAILED' not in data, 'qml_failed')
                if b'FORMAL_UI_READY' in data: facts['ui_ready'] = True
                if b'FORMAL_UI_EXIT_REQUESTED' in data: leave = True
                tails[index] = data[-256:]
            if facts['ui_ready'] and not facts['credentials_removed']:
                _need(_meta(os.stat('credentials.json',dir_fd=area['fd'],follow_symlinks=False)) == credentials_meta,
                      'credentials_changed')
                os.unlink('credentials.json',dir_fd=area['fd']); facts['credentials_removed'] = True
                assets.validate_assets(scope.until)
            if leave or scope.ui.poll() is not None: break
            _need(facts['ui_ready'] or time.monotonic()-launched < 10.0, 'qml_ready_timeout')
            time.sleep(.1)
        facts['reason'] = 'sender_ui_finished' if time.monotonic()<scope.until-1.0 else 'interactive_window_expired'
    except BaseException as error:
        scope.failures.append(error)
        facts['reason'] = error.code if type(error) is SenderUiError else 'sender_ui_failed'
    finally:
        scope.mark_closing()
        if scope.credentials_row is not None and not facts['credentials_removed'] and credentials_meta is not None:
            try:
                _need(_meta(os.stat('credentials.json',dir_fd=area['fd'],follow_symlinks=False)) == credentials_meta,
                      'credentials_changed')
                os.unlink('credentials.json',dir_fd=area['fd']); facts['credentials_removed'] = True
            except BaseException as error: scope.failures.append(error)
        try:
            if candidate is not None: helper._terminate(candidate, baseline['boot'], candidate=True)
            if scope.ui is not None: scope.ui.wait(timeout=3.0)
            facts['candidate_exited'] = not helper._scan(candidate_parent=scope.pid)
        except BaseException as error: scope.failures.append(error)
        facts['owner_closed'] = _close_sender(scope)
        if guard_pid is not None:
            try:
                lock = scope.channel.lock if scope.channel is not None else threading.RLock()
                with lock:
                    if scope.channel is not None: scope.channel.terminal = True
                    if facts['owner_closed'] and facts['candidate_exited']:
                        helper._pipe_write(write_row['fd'],'OWNER_CLOSED_REPORTED\n')
                        helper._pipe_write(write_row['fd'],'RESTORE\n')
                    else: scope.close_fd(write_row)
                    pending = scope.channel.pending if scope.channel is not None else b''
                    end = min(scope.until+135.0,time.monotonic()+65.0)
                    while time.monotonic()<end:
                        pending, frames, eof = helper._pipe_read(read_row['fd'],pending)
                        _need(all(frame in ('RESTORED','FAILED') for frame in frames), 'guardian_result_frame')
                        if frames:
                            _need(len(frames)==1, 'guardian_result_frame')
                            facts['stock_restored'] = frames[0]=='RESTORED'; break
                        if eof: break
                        time.sleep(.1)
                reap_until = min(scope.until+135.0,time.monotonic()+3.0)
                while time.monotonic()<reap_until:
                    pid,status = os.waitpid(guard_pid,os.WNOHANG)
                    if pid==guard_pid:
                        facts['guardian_exited']=os.WIFEXITED(status) and os.WEXITSTATUS(status)==0;break
                    time.sleep(.05)
            except BaseException as error: scope.failures.append(error)
        for row in reversed(scope.rows): scope.close_fd(row)
        facts['worker_fds_closed'] = all(row['closed'] and not row['unknown'] for row in scope.rows)
        facts['resource_pending'] = not (facts['candidate_exited'] and facts['owner_closed'] and
            facts['worker_fds_closed'] and facts['credentials_removed'] and facts['guardian_exited'])
    facts['complete'] = (not scope.failures and not facts['resource_pending'] and
        facts['ui_ready'] and facts['original_ui_exited'] and facts['stock_restored'])
    return facts


def run_fixed(sender_raw, guardian_raw, filecenter_sources):
    """Definition/source gate only until a real sender asset seal exists."""
    sender = _definitions(sender_raw,SENDER_PIN,'fixed_sender_ui_outer')
    helper = _definitions(guardian_raw,GUARDIAN_PIN,'fixed_sender_ui_guardian')
    _need(sender.ROOT == SENDER_ROOT and helper.CONTROL == CONTROL and helper.ASSETS == ASSETS,
          'source_identity')
    _need(SENDER_ASSET_SEAL is not None, 'sender_ui_assets_unsealed')
    # No hypothetical validator, ELF SHA or fake successful stage object is
    # inserted here. The actual versioned asset seal must supply that fixed
    # validator before _run_prepared can become an executable device entry.
    raise SenderUiError('sender_ui_assets_unsealed')


if __name__ == '__main__':
    print('SOURCE_FORMAL_SEND_FILECENTER_UI sender=false filecenter=false guardian=false '
          'credentials=false ui=false auto_rf=false assets_sealed=false deadline_wired=false')
