"""Pure SOURCE maker for one P011 real-lock audio cleanup-cap check.

Only two supplied fixed original modules are loaded, in full and unchanged.
The fixture owns one real Thread/RLock; it never calls play, Popen, GST, HTTP,
Owner, Companion, filesystem or RF. Event/source_fd callbacks are unused seams.
The parent sets its alarm before stdin read and owns transport/stock/raw/sealing.
Importing or making SOURCE does not execute the target or read local files.
"""
import ast
import base64
import hashlib
import zlib

PINS = (
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045,
     'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'))
MODULE_NAMES = ('mta_toolbox_audio', 'mta_filecenter_audio')
SCHEMA = 'p011-filecenter-audio-deadline-v1-real-lock'
RESULT_PREFIX = 'FILECENTER_AUDIO_DEADLINE_RESULT='
TARGET_LIMIT = 48000
TARGET_MAX_LINE = 256
RESULT_FIELDS = frozenset(('schema', 'complete', 'python_version', 'case_count',
    'original_modules_loaded', 'original_class_methods_unchanged',
    'parent_cap_identity_preserved', 'original_runtime_error_received',
    'snapshot_runtime_error_received', 'passive_pending_received',
    'retry_runtime_error_received', 'old_cleanup_cap_identity_preserved',
    'fixture_holder_released', 'fixture_thread_closed', 'original_stop_finished',
    'empty_audio_actors_closed', 'cleanup_pending', 'tickets', 'seam_calls',
    'durations', 'scope'))
SCOPE = dict(actual_lock_and_thread=True, class_methods_modified=False,
    play_called=False, audio_process_started=False, physical_audio_verified=False,
    http_called=False, owner_called=False, companion_called=False,
    filesystem_action_requested=False, rf_called=False, ui_called=False,
    phone_called=False, full_filecenter_deadline_verified=False,
    full_owner_cleanup_verified=False, restoration_verified=False,
    alarm_set_by_target=False, alarm_cancelled_by_target=False)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def source_literal(name, raw):
    payload = base64.b64encode(zlib.compress(raw)).decode('ascii')
    chunks = tuple(payload[index:index + 128] for index in range(0, len(payload), 128))
    need(chunks and all(len(chunk) == 128 for chunk in chunks[:-1]), 'source_chunks')
    return (name + ' = zlib.decompress(base64.b64decode(\n' +
            ''.join('    ' + repr(chunk) + '\n' for chunk in chunks) + '))\n')


TARGET_BODY = r'''
import hashlib, math, sys, threading, time, types

def need(value, code):
    if value is not True:
        raise RuntimeError(code)

def elapsed(start):
    value = float(time.monotonic() - start)
    need(math.isfinite(value) and 0.0 <= value < 20.0, 'fixture_clock')
    return value

def pending(action):
    try:
        action()
    except RuntimeError as error:
        need(type(error) is RuntimeError and error.args == ('audio_state_lock_pending',),
             'fixture_pending_error')
        return True
    raise RuntimeError('fixture_pending_not_received')

started = float(time.monotonic())
need(sys.version_info[:2] == (3, 5) and sys.platform == 'linux', 'fixed_target_python')
need(not any(name in sys.modules for name in MODULE_NAMES), 'audio_namespace_busy')
modules = []
for name, raw, pin in zip(MODULE_NAMES, (BASE_SOURCE, AUDIO_SOURCE), SOURCE_PINS):
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == pin,
         'original_audio_source_pin')
    module = types.ModuleType(name)
    module.__file__ = '<fixed-filecenter-audio-deadline/' + name + '.py>'
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    modules.append(module)
base, audio = modules
cls = audio.FileCenterAudio
need(cls.__bases__ == (base.AudioEngine,) and
     base.AudioEngine.__init__.__globals__ is base.__dict__, 'original_audio_class')
originals = tuple(getattr(cls, name) for name in
    ('__init__', 'stop_audio', 'audio_snapshot', 'actors_closed'))
need(all(method.__globals__ is audio.__dict__ for method in originals), 'original_audio_methods')
constructor, stop, snapshot, closed = originals
parent_cap = float(time.monotonic() + 10.0)
seam_calls = [0, 0]
def event_seam(*args):
    seam_calls[0] += 1
    raise RuntimeError('unused_event_seam_called')
def source_fd_seam(*args):
    seam_calls[1] += 1
    raise RuntimeError('unused_source_fd_seam_called')
value = object.__new__(cls)
constructor(value, '', event_seam, source_fd_seam, parent_until=parent_cap)
lock = value.lock
entered, release, ended = threading.Event(), threading.Event(), threading.Event()
holder_released, holder_errors = [False], []
def hold():
    try:
        with lock:
            entered.set()
            holder_released[0] = release.wait(3.0)
    except BaseException as error:
        holder_errors.append(error)
    finally:
        ended.set()
holder = threading.Thread(target=hold)
holder.daemon = True
facts = dict(schema=SCHEMA, complete=False, python_version=tuple(sys.version_info[:3]),
    case_count=1, original_modules_loaded=True, original_class_methods_unchanged=False,
    parent_cap_identity_preserved=False, original_runtime_error_received=False,
    snapshot_runtime_error_received=False, passive_pending_received=False,
    retry_runtime_error_received=False, old_cleanup_cap_identity_preserved=False,
    fixture_holder_released=False, fixture_thread_closed=False, original_stop_finished=False,
    empty_audio_actors_closed=False, cleanup_pending=True, tickets=0,
    seam_calls=(0, 0), durations={}, scope=SCOPE)
failure = None
holder_started = False
try:
    holder.start()
    holder_started = True
    wait_started = float(time.monotonic())
    need(entered.wait(1.0) and not ended.is_set(), 'fixture_holder_not_entered')
    facts['durations']['holder_enter'] = elapsed(wait_started)
    cap = float(time.monotonic() + 0.12)
    phase = float(time.monotonic())
    facts['original_runtime_error_received'] = pending(lambda:stop(value, cleanup_until=cap))
    facts['durations']['initial_stop'] = elapsed(phase)
    need(time.monotonic() >= cap and facts['durations']['initial_stop'] <= 0.60 and
         not ended.is_set() and value.cleanup_pending is True, 'fixture_stop_deadline')
    saved_cap = value.cleanup_until
    need(saved_cap is cap and value.lock is lock, 'original_cleanup_cap_identity')
    phase = float(time.monotonic())
    facts['snapshot_runtime_error_received'] = pending(lambda:snapshot(value))
    facts['durations']['pending_snapshot'] = elapsed(phase)
    phase = float(time.monotonic())
    facts['passive_pending_received'] = closed(value) is False
    facts['durations']['passive_closed'] = elapsed(phase)
    later_cap = float(time.monotonic() + 2.0)
    phase = float(time.monotonic())
    facts['retry_runtime_error_received'] = pending(lambda:stop(value, cleanup_until=later_cap))
    facts['durations']['later_cap_retry'] = elapsed(phase)
    facts['old_cleanup_cap_identity_preserved'] = value.cleanup_until is saved_cap
    need(facts['passive_pending_received'] and facts['old_cleanup_cap_identity_preserved'] and
         not ended.is_set() and all(facts['durations'][name] <= 0.25 for name in
             ('pending_snapshot', 'passive_closed', 'later_cap_retry')), 'fixture_pending_budget')
except BaseException as error:
    failure = error
finally:
    phase = float(time.monotonic())
    release.set()
    if holder_started:
        holder.join(timeout=2.0)
    facts['durations']['fixture_release_join'] = elapsed(phase)
    facts['fixture_holder_released'] = holder_released[0] is True
    facts['fixture_thread_closed'] = holder_started and ended.is_set() and not holder.is_alive()
    if not facts['fixture_thread_closed'] or holder_errors or not facts['fixture_holder_released']:
        if failure is None:
            failure = RuntimeError('fixture_thread_pending')
    elif value.lock is lock:
        try:
            phase = float(time.monotonic())
            stop(value, cleanup_until=float(time.monotonic() + 0.50))
            facts['durations']['released_original_stop'] = elapsed(phase)
            facts['original_stop_finished'] = True
            facts['empty_audio_actors_closed'] = closed(value) is True
        except BaseException as error:
            if failure is None:
                failure = error
    facts['original_class_methods_unchanged'] = all(getattr(cls, name) is method
        for name, method in zip(('__init__', 'stop_audio', 'audio_snapshot', 'actors_closed'), originals))
    facts['parent_cap_identity_preserved'] = value.parent_until is parent_cap and value._parent_until_original is parent_cap
    facts['cleanup_pending'] = value.cleanup_pending
    facts['tickets'] = len(value.tickets)
    facts['seam_calls'] = tuple(seam_calls)
    facts['durations']['total'] = elapsed(started)
    if failure is None:
        try:
            need(facts['original_class_methods_unchanged'] and facts['parent_cap_identity_preserved'] and
                 facts['original_stop_finished'] and facts['empty_audio_actors_closed'] and
                 facts['cleanup_pending'] is False and facts['tickets'] == 0 and
                 facts['seam_calls'] == (0, 0) and value.audio is None and value.audio_reader is None and
                 value.audio_reader_stop is None and value.cleanup_until is None, 'fixture_final_audio_state')
            facts['complete'] = True
        except BaseException as error:
            failure = error
    print(RESULT_PREFIX + repr(facts))
if failure is not None:
    raise failure
'''


def make_source(inputraws):
    need(type(inputraws) is dict and set(inputraws) == {row[0] for row in PINS}, 'fixed_audio_inputs')
    values = tuple(inputraws[row[0]] for row in PINS)
    for raw, row in zip(values, PINS):
        need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:], 'fixed_audio_pin')
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        need(all(isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign,
                                  ast.FunctionDef, ast.ClassDef)) for node in tree.body), 'fixed_audio_definitions')
    constants = ('MODULE_NAMES = ' + repr(MODULE_NAMES) + '\n' +
                 'SOURCE_PINS = ' + repr(tuple(row[1:] for row in PINS)) + '\n' +
                 'SCHEMA = ' + repr(SCHEMA) + '\n' +
                 'RESULT_PREFIX = ' + repr(RESULT_PREFIX) + '\n' +
                 'SCOPE = ' + repr(SCOPE) + '\n')
    # Keep source lines below the original bounded parent line cap; no source
    # module is filtered, normalized, AST-rewritten, imported or executed here.
    constants = constants.replace('SCOPE = ' + repr(SCOPE),
        'SCOPE = dict(\n' + ''.join('    ' + key + '=' + repr(value) + ',\n'
                                    for key, value in SCOPE.items()) + ')')
    raw = ('import base64, zlib\n' + constants + source_literal('BASE_SOURCE', values[0]) +
           source_literal('AUDIO_SOURCE', values[1]) + TARGET_BODY).encode('ascii')
    need(len(raw) <= TARGET_LIMIT and max(map(len, raw.splitlines())) <= TARGET_MAX_LINE,
         'audio_deadline_target_budget')
    ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return raw
