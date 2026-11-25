"""Fixed sealed sender/FileCenter UI-v7 socket identity closure composition.

The actual v3 Boot/Owner owns one Companion and consumes the same parent
600-second activity window. Its deadline-v2 FileCenter/audio cleanup paths
receive the original Owner cleanup deadline; this worker never renews a cap.
The real guardian precedes Owner credentials and retains actual child ACKs.
The pinned PC-built assets are independently versioned; validate_assets does
read-only authentication before any credentials or original-UI suspension.
Default main is SOURCE-only. Only an explicit run_fixed call may launch this
fixed temporary UI. No automatic RF action or receiver worker is dispatched.
PC source/build validation is not device, restoration or phone acceptance.
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

SENDER_PIN = (24059, '5b827482ee82e9edcf4bff07ad75e24166a4a1bda3d949a1f4f617a93dd488c3')
GUARDIAN_PIN = (43993, '30b7157cabf3dd75eb82a671a343a106c1f9e688c1ad60e12c7b8e172ffc255e')
ASSETS_PIN = (12526, 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')
SENDER_ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v5'
SENDER_PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v5'
PROFILE = 'send-interactive-v1'
SESSION = 'a44b98dd639095d9063c9e1a'
ASSETS = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-send-filecenter-ui-v7'
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
STOCK_PINS = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
)
# Actual PC-built immutable assets; target authentication is still required.
SENDER_ASSET_SEAL = (SESSION, ASSETS, (1603, '34cf33ad9ad501f49ac819856c4e0b3bb0e351d6eb0f82299402900962699df7'))
FILECENTER_PINS = (
    ('mta_toolbox_json', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('mta_toolbox_storage', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 15082, '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
    ('mta_filecenter_storage', 4581, '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('mta_filecenter_companion', 25966, '51f212ef07e0e323cc3803cfd2583ec29867ce0bbf7daff9129ad51d4f6eeeb3'),
)
_RETAINED = None
DIAGNOSTIC_STAGES = ('scope_created', 'assets_validation', 'stock_baseline',
    'control_create', 'guardian_fork', 'guardian_arm_wait', 'sender_construct',
    'sender_start', 'sender_identity', 'filecenter_create', 'guardian_bind',
    'mta_credentials', 'filecenter_credentials', 'ui_credentials',
    'stock_suspend', 'candidate_start', 'ui_loop', 'candidate_stop',
    'sender_close', 'guardian_restore', 'worker_fd_close')
DIAGNOSTIC_LIMIT = 32768


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


def _diagnostic_mark(scope, stage):
    _need(stage in DIAGNOSTIC_STAGES and type(scope.diagnostic_stages) is list and
          len(scope.diagnostic_stages) < 32, 'diagnostic_stage')
    scope.diagnostic_stages.append(stage)


# These are literal control errors from the frozen original closing paths,
# never arbitrary exception text. An unknown/new code is represented by None.
CLOSE_ERROR_CODES = ('wrong_worker', 'deadline', 'clock_unknown', 'cleanup_cap_changed',
    'owner_constructor_unknown', 'loader_constructor_unknown', 'sender_cleanup_changed',
    'owner_changed', 'state_source_changed', 'close_unknown', 'socket_close_unknown',
    'filecenter_original_changed', 'filecenter_partial_unknown', 'state_operation_pending',
    'root_changed', 'anchor_changed', 'source_changed', 'fd_close_unknown',
    'audio_guardian_source', 'audio_guardian_pipe', 'audio_guardian_clock',
    'audio_guardian_deadline', 'audio_guardian_missing', 'audio_guardian_ack_timeout',
    'audio_guardian_eof', 'audio_guardian_ack', 'audio_guardian_cancel',
    'audio_guardian_ticket', 'audio_guardian_command', 'audio_wrapper_exited',
    'audio_wrapper_not_stopped', 'audio_guardian_actor', 'window_changed')


def _observed_bool(value):
    return value if type(value) is bool else None


def _error_records(errors, limit=16, frame_limit=32, chain_limit=8):
    """Only retained original exceptions; no args, locals, filenames or payload."""
    _need(type(errors) is list and 0 < limit <= 16 and
          0 < frame_limit <= 32 and 0 < chain_limit <= 8, 'diagnostic_exception_shape')
    records, truncated = [], len(errors) > limit
    for original in errors[:limit]:
        _need(isinstance(original, BaseException), 'diagnostic_exception')
        current, relation, seen, chain = original, 'original', [], []
        while current is not None and len(chain) < chain_limit:
            if any(current is retained for retained in seen):
                truncated = True; break
            seen.append(current)
            kind = type(current).__name__
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}', kind): kind = 'UnknownException'
            number = current.errno if isinstance(current, OSError) else None
            if type(number) is not int or not 0 <= number <= 65535: number = None
            code = getattr(current, 'code', None)
            if type(code) is not str or code not in CLOSE_ERROR_CODES: code = None
            frames, trace = [], current.__traceback__
            while trace is not None and len(frames) < frame_limit:
                module = trace.tb_frame.f_globals.get('__name__')
                function = trace.tb_frame.f_code.co_name
                if type(module) is not str or not re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,127}', module):
                    module = 'unknown_module'
                if (type(function) is not str or
                        not (re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', function) or
                             function in ('<module>', '<lambda>', '<listcomp>', '<genexpr>'))):
                    function = 'unknown_function'
                line = trace.tb_lineno
                _need(type(line) is int and 0 <= line < (1 << 31), 'diagnostic_line')
                frames.append((module, function, line)); trace = trace.tb_next
            if trace is not None: truncated = True
            chain.append(dict(relation=relation, kind=kind, errno=number, code=code, frames=tuple(frames)))
            if current.__cause__ is not None:
                current, relation = current.__cause__, 'cause'
            elif current.__context__ is not None and not current.__suppress_context__:
                current, relation = current.__context__, 'context'
            else: current = None
        if current is not None: truncated = True
        records.append(tuple(chain))
    return dict(failure_count=len(errors), errors=tuple(records), truncated=truncated)


def _retained_error_observation(value, attributes, list_name=None, rows_name=None):
    """Borrow already-held errors only; no closure, I/O or child predicate call."""
    errors = []
    def retain(error):
        if isinstance(error, BaseException) and not any(error is row for row in errors):
            errors.append(error)
    for name in attributes: retain(getattr(value, name, None))
    original = getattr(value, list_name, None) if list_name is not None else None
    if type(original) is list:
        for error in original[:64]: retain(error)
    rows = getattr(value, rows_name, None) if rows_name is not None else None
    if type(rows) is list:
        for row in rows[:64]:
            if type(row) is dict:
                for name in ('failure', 'close_failure', 'close_error', 'cleanup_failure', 'error'):
                    error = row.get(name)
                    # A successful EBADF proof is not itself a closing failure.
                    if name != 'close_error' or row.get('closed') is not True: retain(error)
    result = _error_records(errors, limit=4, frame_limit=8, chain_limit=2)
    result['original_failure_list_count'] = len(original) if type(original) is list else None
    result['original_row_count'] = len(rows) if type(rows) is list else None
    result['inventory_truncated'] = (type(original) is list and len(original) > 64 or
                                    type(rows) is list and len(rows) > 64)
    return result


def _row_observation(rows):
    if type(rows) is not list: return None
    limited = rows[:256]
    return dict(count=len(rows), inspected=len(limited),
        closed_true=sum(type(row) is dict and row.get('closed') is True for row in limited),
        closed_false=sum(type(row) is dict and row.get('closed') is False for row in limited),
        closed_none=sum(type(row) is dict and type(row.get('closed')) is not bool for row in limited),
        ended_true=sum(type(row) is dict and row.get('ended') is True for row in limited),
        ended_false=sum(type(row) is dict and row.get('ended') is False for row in limited),
        ended_none=sum(type(row) is dict and type(row.get('ended')) is not bool for row in limited),
        unknown_true=sum(type(row) is dict and row.get('unknown') is True for row in limited),
        inventory_truncated=len(rows) > 256)


def _socket_close_observation(owner):
    """Read finite actual receipt fields only; never validate/grant closure."""
    values = getattr(owner, 'socket_close_receipts', None)
    if (type(values) is not list or
            values is not getattr(owner, '_socket_close_receipts_original', None)):
        return dict(available=False, count=None, rows=(), truncated=False)
    rows = []
    for value in values[:128]:
        if type(value) is not dict:
            rows.append(dict(outcome='error', close_return_none=None,
                             post_fileno_minus_one=None, sealed_identity=False))
            continue
        outcome = value.get('post_outcome')
        if outcome not in ('none','badfd','reused','same','error'): outcome = 'error'
        seal = value.get('sealed')
        rows.append(dict(outcome=outcome,
            close_return_none=_observed_bool(value.get('close_return_none')),
            post_fileno_minus_one=_observed_bool(value.get('post_fileno_minus_one')),
            sealed_identity=type(seal) is tuple and seal is value.get('sealed_retained')))
    return dict(available=True, count=len(values), rows=tuple(rows), truncated=len(values)>128)


def _close_snapshot(scope, observation):
    """Finite fields of original retained instances, NOT recomputed close receipts."""
    sender, ticket = scope.sender, scope.sender_ticket
    if (type(ticket) is not dict or ticket.get('constructed') is not True or
            sender is not ticket.get('original') or type(sender) is not ticket.get('creator')):
        observation['snapshot_available'] = False
        return
    observation['sender'] = {name:_observed_bool(getattr(sender, name, None)) for name in
        ('close_called', 'close_complete', 'pending', 'owner_close_return')}
    observation['sender_rows'] = _row_observation(sender.rows)
    observation['sender_failures'] = _retained_error_observation(
        sender, ('failure', 'close_failure'), 'failures', 'rows')
    loader_ticket = sender.loader_ticket
    loader = sender.loader
    if (type(loader_ticket) is dict and loader_ticket.get('constructed') is True and
            loader is loader_ticket.get('partial') and type(loader) is loader_ticket.get('creator')):
        observation['loader_pending'] = _observed_bool(getattr(loader, 'pending', None))
        observation['loader_rows'] = _row_observation(loader.rows)
        observation['loader_failures'] = _retained_error_observation(
            loader, ('failure',), 'failures', 'rows')
    owner, owner_ticket = sender.owner, sender.owner_ticket
    if (type(owner_ticket) is not dict or owner_ticket.get('constructed') is not True or
            owner is not owner_ticket.get('partial') or type(owner) is not owner_ticket.get('creator')):
        observation['owner_snapshot_available'] = False
        return
    observation['owner_snapshot_available'] = True
    observation['socket_close_observations'] = _socket_close_observation(owner)
    observation['owner'] = {name:_observed_bool(getattr(owner, name, None)) for name in
        ('close_called', 'close_complete', 'stop_called', 'state_close_called', 'state_close_return',
         'directory_close_called', 'directory_close_complete', 'cleanup_deadline_expired')}
    observation['owner_cleanup_clock_failure_present'] = owner.cleanup_clock_failure is not None
    observation['owner_rows'] = {name:_row_observation(getattr(owner, name, None))
                                for name in ('assets', 'requests', 'threads')}
    observation['owner_failures'] = _retained_error_observation(
        owner, ('failure', 'loop_failure', 'cleanup_clock_failure'), 'failures', 'requests')
    fc, fc_ticket = scope.filecenter, scope.filecenter_ticket
    if (type(fc_ticket) is dict and fc_ticket is owner.filecenter_ticket and
            fc_ticket is owner._filecenter_ticket_original and
            fc is fc_ticket.get('original') and type(fc) is fc_ticket.get('cls')):
        observation['filecenter'] = {name:_observed_bool(getattr(fc, name, None)) for name in
            ('close_called', 'close_complete', 'state_complete', 'server_complete', 'start_returned')}
        observation['filecenter_ticket'] = {name:_observed_bool(fc_ticket.get(name)) for name in
            ('create_returned', 'close_called', 'close_return')}
        observation['filecenter_failures'] = _retained_error_observation(
            fc, ('failure',), 'cleanup_failures', 'media')
        observation['filecenter_ticket_failures'] = _error_records(
            [fc_ticket[name] for name in ('failure', 'close_failure')
             if isinstance(fc_ticket.get(name), BaseException)], limit=4, frame_limit=8, chain_limit=2)
        audio = fc.audio
        observation['audio_cleanup_pending'] = _observed_bool(getattr(audio, 'cleanup_pending', None))
        observation['audio_failures'] = _retained_error_observation(
            audio, (), None, 'tickets')
    channel = scope.channel
    if channel is not None:
        observation['channel'] = {name:_observed_bool(getattr(channel, name, None)) for name in
                                  ('closing', 'bound', 'terminal')}
        observation['channel_failures'] = _retained_error_observation(
            channel, ('failure',), None, 'rows')
    observation['snapshot_available'] = True


def _exception_projection(errors, stages, close_observation=None):
    """Bounded privacy projection only; observations never grant closure."""
    _need(type(errors) is list and type(stages) is list and
          len(stages) <= 32 and all(stage in DIAGNOSTIC_STAGES for stage in stages),
          'diagnostic_shape')
    result = _error_records(errors)
    result.update(kind='sender-ui-diagnostic-v6', stages=tuple(stages),
                  close_observation=close_observation)
    raw = (repr(result) + '\n').encode('ascii')
    if len(raw) > DIAGNOSTIC_LIMIT:
        # Keep actual counts/booleans while explicitly refusing a full trace.
        result['errors'] = ()
        result['truncated'] = True
        if type(close_observation) is dict:
            close_observation['projection_truncated'] = True
            for name, value in close_observation.items():
                if type(value) is dict and 'errors' in value:
                    value['errors'] = (); value['truncated'] = True
        raw = (repr(result) + '\n').encode('ascii')
    _need(len(raw) <= DIAGNOSTIC_LIMIT, 'diagnostic_budget')
    return raw

def _write_diagnostic(scope):
    row = scope.diagnostic_row
    if row is None: return False
    _need(any(row is original for original in scope.rows) and
          row['fd'] is row['original_fd'] and not row['unknown'] and
          not row['closed'] and not row['attempted'] and
          _meta(os.fstat(row['fd'])) == row['metadata'], 'diagnostic_fd_changed')
    raw = _exception_projection(scope.failures, scope.diagnostic_stages, scope.close_observation)
    _need(os.write(row['fd'], raw) == len(raw), 'diagnostic_write')
    os.fsync(row['fd'])
    return True


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
        self.diagnostic_row, self.diagnostic_stages = None, ['scope_created']
        self.close_observation = None
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
    """Real v3 Boot/Owner producer, with partial original retained first."""
    scope.check()
    module, creator = scope.sender_module, scope.sender_module.FixedSendSession
    _need(scope.sender is None and module.ROOT == SENDER_ROOT and
          module.PHYSICAL_ROOT == SENDER_PHYSICAL_ROOT, 'sender_source')
    ticket = dict(creator=creator, original=None, constructed=False,
                  started=False, start_return=None, failure=None, close_return=None)
    scope.sender_ticket = ticket
    scope.sender = ticket['original'] = object.__new__(creator)
    try:
        _diagnostic_mark(scope, 'sender_construct')
        creator.__init__(scope.sender, scope.until, scope.cleanup_until, True, PROFILE)
        ticket['constructed'] = True
        scope.check()
        _diagnostic_mark(scope, 'sender_start')
        ticket['start_return'] = creator.start(scope.sender)
        _need(ticket['start_return'] is scope.sender, 'sender_start_return')
        ticket['started'] = True
        owner = scope.sender.owner
        _diagnostic_mark(scope, 'sender_identity')
        _need(owner is scope.sender.owner_ticket['partial'] and
              type(owner) is scope.sender.owner_module.FixedStateServiceOwner and
              owner.until is scope.until and owner.worker is scope.worker and
              owner._startup_namespace_original is scope.sender.owner_module.__dict__,
              'sender_owner_changed')
        # Only this real Owner loads the nine sources and invokes its original
        # retainer. There is deliberately no UI-side Companion/create fallback.
        try:
            _diagnostic_mark(scope, 'filecenter_create')
            scope.filecenter = owner.create_filecenter(source_rows)
        finally:
            scope.filecenter_ticket = owner.filecenter_ticket
        ticket_fc = scope.filecenter_ticket
        _need(ticket_fc is owner._filecenter_ticket_original and
              ticket_fc['original'] is scope.filecenter and ticket_fc['create_returned'] and
              owner._filecenter_current() and
              scope.filecenter.audio.parent_until is scope.until and
              scope.filecenter.audio._parent_until_original is scope.until, 'filecenter_original')
        _diagnostic_mark(scope, 'guardian_bind')
        scope.channel.bind(scope.filecenter.audio, ticket_fc['modules'][6]['module'], scope.filecenter)
        _need(scope.channel.current() and owner._filecenter_current(), 'audio_guardian_source')
        _diagnostic_mark(scope, 'mta_credentials')
        endpoint = creator.credentials(scope.sender)
        _diagnostic_mark(scope, 'filecenter_credentials')
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
    """Keep original short circuit/order/calls; observe only actually called predicates."""
    observation = dict(kind='sender-ui-close-observation-v6', snapshot_available=False,
        sender_close=dict(called=False, returned=None),
        sender_closed=dict(called=False, returned=None),
        filecenter_closed=dict(called=False, returned=None, bypass=None),
        channel_settled=dict(called=False, returned=None, bypass=None))
    scope.close_observation = observation
    scope.mark_closing()
    if scope.channel is not None and scope.channel.bound:
        try: scope.channel.prevent_new()
        except BaseException as error: scope.failures.append(error)
    if scope.sender_ticket is None:
        observation['sender_absent'] = True
        return True
    ticket = scope.sender_ticket
    if not ticket['constructed']:
        observation['sender_constructed'] = False
        return False  # Preserve partial ctor; do not invoke methods on guesses.
    try:
        # Exactly the former first call, before the original cleanup identity gate.
        observation['sender_close']['called'] = True
        ticket['close_return'] = ticket['creator'].close(scope.sender)
        observation['sender_close']['returned'] = _observed_bool(ticket['close_return'])
        if scope.sender.owner is not None and scope.sender.owner_ticket['constructed']:
            owner = scope.sender.owner
            _need(owner.cleanup_until is owner._cleanup_until_original and
                  type(owner.cleanup_until) is float and math.isfinite(owner.cleanup_until) and
                  owner.cleanup_until <= scope.cleanup_until, 'sender_cleanup_changed')
        if ticket['close_return'] is not True: return False
        observation['sender_closed']['called'] = True
        value = ticket['creator']._closed(scope.sender)
        observation['sender_closed']['returned'] = _observed_bool(value)
        if not value: return value
        if scope.filecenter_ticket is None:
            observation['filecenter_closed']['bypass'] = 'no_filecenter'
        else:
            observation['filecenter_closed']['called'] = True
            value = scope.sender.owner._filecenter_closed()
            observation['filecenter_closed']['returned'] = _observed_bool(value)
            if not value: return value
        if scope.channel is None:
            observation['channel_settled']['bypass'] = 'no_channel'
            return True
        if not scope.channel.bound:
            observation['channel_settled']['bypass'] = 'unbound_channel'
            return True
        observation['channel_settled']['called'] = True
        value = scope.channel.settled()
        observation['channel_settled']['returned'] = _observed_bool(value)
        return value
    except BaseException as error:
        scope.failures.append(error)
        return False
    finally:
        # Read held inventory only. A diagnostic failure cannot change the
        # original closing return, add a close attempt, or grant a receipt.
        try: _close_snapshot(scope, observation)
        except BaseException as error:
            observation['snapshot_failed'] = True
            observation['snapshot_error'] = _error_records([error], limit=1, frame_limit=8, chain_limit=2)

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


def _run_prepared(sender_module, helper, source_rows, assets, smoke_only=False):
    """Actual sender-only choreography; caller must have sealed real assets."""
    global _RETAINED
    _need(type(smoke_only) is bool, 'smoke_profile')
    _need(not any(name.startswith(('mta_', 'p011_')) for name in sys.modules), 'namespace_busy')
    scope = _UiScope(sender_module, helper)
    _RETAINED = scope  # Strong original before any IO/constructor/fork.
    facts = dict(complete=False, ui_ready=False, credentials_removed=False,
                 original_ui_exited=False, candidate_exited=False,
                 owner_closed=False, guardian_exited=False, stock_restored=False,
                 worker_fds_closed=False, resource_pending=True,
                 automatic_rf_action=False, receive_worker_started=False,
                 filecenter_parent_deadline_verified=False,
                 filecenter_parent_deadline_wired=False, smoke_requested=smoke_only,
                 automatic_stop_seconds=20 if smoke_only else 0, reason='not_started')
    guard_pid = None
    baseline = candidate = control = write_row = read_row = None
    credentials_meta = None
    try:
        scope.check()
        _diagnostic_mark(scope, 'assets_validation')
        asset_facts = assets.validate_assets(scope.until)
        for path in ('/mnt/data/p011-toolbox/native.lock', '/mnt/data/p011-toolbox/bili-awake.lock',
                     '/tmp/p011-menutest.lock', '/mnt/data/p011-menu'):
            _need(not os.path.lexists(path), 'other_ui_trial')
        _diagnostic_mark(scope, 'stock_baseline')
        baseline, environment = _stock(scope)
        cwd = os.readlink('/proc/%d/cwd' % baseline['original']['pid'])
        helper._no_core()
        anchor = scope.open_fd('/var/volatile/tmp', os.O_RDONLY | os.O_DIRECTORY)
        _need(anchor['metadata'][2:5] == (stat.S_IFDIR | 0o1777, 0, 0), 'unsafe_control_anchor')
        _diagnostic_mark(scope, 'control_create')
        os.mkdir(CONTROL_NAME, 0o700, dir_fd=anchor['fd'])
        control = scope.open_fd(CONTROL_NAME, os.O_RDONLY | os.O_DIRECTORY, parent=anchor['fd'])
        _need(control['metadata'][2:5] == (stat.S_IFDIR | 0o700, 0, 0), 'unsafe_control')
        baseline['control_meta'] = control['metadata'][:5]
        logs = tuple(scope.raw_file(control['fd'], name) for name in
                     ('guardian.stdout.raw', 'guardian.stderr.raw'))
        ui_logs = tuple(scope.raw_file(control['fd'], name) for name in
                        ('candidate.stdout.raw', 'candidate.stderr.raw'))
        scope.diagnostic_row = scope.raw_file(control['fd'], 'worker.diagnostic.raw')
        to_guard = tuple(scope._row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        from_guard = tuple(scope._row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        worker = helper._proc(os.getpid())
        _need(scope.owner is None and threading.active_count() == 1, 'fork_boundary')
        sys.stdout.flush(); sys.stderr.flush()
        _diagnostic_mark(scope, 'guardian_fork')
        guard_pid = os.fork()
        if guard_pid == 0:
            helper._guardian(scope, to_guard[0]['fd'], from_guard[1]['fd'], logs, baseline, worker)
            os._exit(3)
        scope.guardian = helper._proc(guard_pid)
        write_row, read_row = to_guard[1], from_guard[0]
        for row in (to_guard[0], from_guard[1]) + logs:
            _need(scope.close_fd(row), 'guardian_parent_fd_close')
        pending, armed, arm_until = b'', False, min(scope.until, time.monotonic()+5.0)
        _diagnostic_mark(scope, 'guardian_arm_wait')
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
        facts['filecenter_parent_deadline_wired'] = True
        # No full-path reopen after validation: keep the actual parent/child
        # FD chain, using the validator's original credential-only bindings.
        parent, asset_edges = None, []
        for name, metadata in asset_facts['credential_directory_bindings']:
            row = scope.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent)
            _need(row['metadata'][:5] == metadata, 'asset_directory_changed')
            asset_edges.append((parent,name,row)); parent = row['fd']
        _need(asset_edges and asset_edges[-1][1] == SESSION, 'asset_directory_changed')
        area = asset_edges[-1][2]
        _diagnostic_mark(scope, 'ui_credentials')
        credentials = scope.raw_file(area['fd'], 'credentials.json')
        scope.credentials_row = credentials
        codec = scope.filecenter_ticket['modules'][0]['module']
        private = codec.dumps(dict(session=SESSION, endpoint=endpoint['endpoint'], token=endpoint['token'],
            toolboxEndpoint=toolbox['endpoint'], toolboxToken=toolbox['token'])).encode('utf-8')
        _need(len(private) <= 1024 and os.write(credentials['fd'], private) == len(private), 'credential_write')
        os.fsync(credentials['fd']); credentials_meta = _meta(os.fstat(credentials['fd']))
        _need(scope.close_fd(credentials), 'credential_close')
        endpoint = toolbox = private = None
        _diagnostic_mark(scope, 'stock_suspend')
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
        _diagnostic_mark(scope, 'candidate_start')
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
        # Fixed HOST smoke policy only shortens UI activity. It never changes
        # the original Scope/Owner/guardian activity or cleanup deadline.
        ui_until = min(scope.until-1.0, launched+20.0) if smoke_only else scope.until-1.0
        _diagnostic_mark(scope, 'ui_loop')
        while time.monotonic() < ui_until:
            scope.check()
            _need(scope.owner.start_complete and scope.owner.thread.is_alive() and
                  scope.owner._filecenter_current() and scope.channel.current(), 'sender_original_changed')
            _need(helper._alive(helper._refresh(scope.guardian)), 'guardian_missing')
            leave = False
            for index, row in enumerate(readers):
                _need(os.fstat(row['fd']).st_size <= 4194304, 'ui_log_budget')
                data = tails[index]+os.read(row['fd'],65536)
                _need(b'FORMAL_UI_FAILED' not in data and b'FORMAL_SCENE_FAILED' not in data, 'qml_failed')
                if b'FORMAL_UI_READY' in data:
                    if not facts['ui_ready']: print('P011_MTA_DIAGNOSTIC_UI_READY', flush=True)
                    facts['ui_ready'] = True
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
        facts['reason'] = ('sender_ui_smoke_finished' if smoke_only else
            'sender_ui_finished' if time.monotonic()<scope.until-1.0 else 'interactive_window_expired')
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
        _diagnostic_mark(scope, 'candidate_stop')
        try:
            if candidate is not None: helper._terminate(candidate, baseline['boot'], candidate=True)
            if scope.ui is not None: scope.ui.wait(timeout=3.0)
            facts['candidate_exited'] = not helper._scan(candidate_parent=scope.pid)
        except BaseException as error: scope.failures.append(error)
        _diagnostic_mark(scope, 'sender_close')
        facts['owner_closed'] = _close_sender(scope)
        _diagnostic_mark(scope, 'guardian_restore')
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
        _diagnostic_mark(scope, 'worker_fd_close')
        for row in reversed(scope.rows):
            if row is not scope.diagnostic_row: scope.close_fd(row)
        try: _write_diagnostic(scope)
        except BaseException as error: scope.failures.append(error)
        if scope.diagnostic_row is not None: scope.close_fd(scope.diagnostic_row)
        facts['worker_fds_closed'] = all(row['closed'] and not row['unknown'] for row in scope.rows)
        facts['resource_pending'] = not (facts['candidate_exited'] and facts['owner_closed'] and
            facts['worker_fds_closed'] and facts['credentials_removed'] and facts['guardian_exited'])
    facts['complete'] = (not scope.failures and not facts['resource_pending'] and
        facts['ui_ready'] and facts['original_ui_exited'] and facts['stock_restored'])
    return facts


def _validate_filecenter_sources(filecenter_sources):
    """Pure pinned bytes validation only; no runtime/actor/admission receipt."""
    _need(type(filecenter_sources) is tuple and len(filecenter_sources) == len(FILECENTER_PINS),
          'filecenter_source_shape')
    for row, pin in zip(filecenter_sources, FILECENTER_PINS):
        _need(type(row) is tuple and len(row) == 2 and row[0] == pin[0] and
              type(row[1]) is bytes and (len(row[1]), hashlib.sha256(row[1]).hexdigest()) == pin[1:],
              'filecenter_source_pin')
    _need(sum(len(row[1]) for row in filecenter_sources) == 99972 and
          sum(len(row[1]) for row in filecenter_sources) <= 131072, 'filecenter_source_budget')
    return filecenter_sources


def run_fixed(sender_raw, guardian_raw, filecenter_sources, assets_raw, smoke_only=False):
    """Explicit sealed fixed entry; no action is initiated from SOURCE main."""
    sender = _definitions(sender_raw, SENDER_PIN, 'fixed_sender_ui_outer')
    helper = _definitions(guardian_raw, GUARDIAN_PIN, 'fixed_sender_ui_guardian')
    assets = _definitions(assets_raw, ASSETS_PIN, 'fixed_sender_ui_assets')
    _need(sender.ROOT == SENDER_ROOT and sender.PHYSICAL_ROOT == SENDER_PHYSICAL_ROOT and
          helper.SESSION == assets.SESSION == SESSION and helper.CONTROL == CONTROL and
          helper.ASSETS == assets.REMOTE == ASSETS and
          helper.CANDIDATE == ASSETS+'/Z03.mta-ui-candidate' and
          SENDER_ASSET_SEAL == (SESSION, ASSETS, assets.MANIFEST_PIN), 'source_identity')
    _validate_filecenter_sources(filecenter_sources)
    # The private validator is not canonical and never loads FC9. Only the
    # retained actual sender Owner performs that one load/create after guardian.
    return _run_prepared(sender, helper, filecenter_sources, assets, smoke_only=smoke_only)


if __name__ == '__main__':
    print('SOURCE_FORMAL_SEND_FILECENTER_UI_V4 sender=false filecenter=false guardian=false '
          'credentials=false ui=false auto_rf=false assets_sealed=true deadline_wired=true')
