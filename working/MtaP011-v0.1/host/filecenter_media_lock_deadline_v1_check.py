"""SOURCE by default; --run starts one focused WSL real HTTP/media-lock worker.

Only affected mutex paths are exercised, in both actual FC9 dependency families.
Private Companion/root/guard and a shorter Handler.setup are explicit HOST
fixtures, not native Owner admission. No old test/main, audio child, ADB, RF,
phone, graph generation, package staging or blocking-file-IO claim is made.
Root is the sole executor. Raw streams, exit and input bytes remain private.
"""
import argparse
import ast
from contextlib import contextmanager
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/filecenter_media_lock_deadline_v1_check.py'
CMD = 'HOST_MTA_FILECENTER_MEDIA_LOCK_DEADLINE_V1_CHECK.cmd'
GENERATOR = 'candidate/filecenter-media-lock-deadline-v1/generate_candidate.py'
DONOR = 'tests/test_filecenter_http_parent_cap_v1.py'
PARENT = 'host/filecenter_http_parent_cap_v1_check.py'
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
SOURCE_PINS = (
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069,
     'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
     '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114,
     'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080,
     'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045,
     'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732,
     'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
    ('candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py', 4581,
     '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757,
     'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'),
    ('candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py', 26088,
     '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f'),
    ('candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py', 33630,
     '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba'),
    ('candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py', 27656,
     '57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd'),
    ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py', 35198,
     '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca'),
    (GENERATOR, 10637, 'e7e2b8e4d82e2efc8bb5bca10f9415227f946a197976cd58b9c9c26b0ad0059b'),
    (DONOR, 21691, 'a0529db68247d85d06d0289397f350d09c1d7a1bf66e9f39ca45fb96b291912c'),
    (PARENT, 11111, '8bc46316dd2d3900ad602e85900f78d9893a57afa300ca49129b0267fc0c6938'),
    ('candidate/filecenter-media-lock-deadline-v1/send/exactsource-delta.json', 4751,
     '690bbf7a2d8e79529567e4eba34086ff498020a9167be51d3ee306c9f7e710a6'),
    ('candidate/filecenter-media-lock-deadline-v1/receive/exactsource-delta.json', 4760,
     '8f5d938dd5aac90374b1cf8be999756e35ba645e11f362c8726ad24c388cea35'),
)
NAMES = ('mta_toolbox_json', 'mta_toolbox_minhttp', 'mta_toolbox_storage',
         'mta_toolbox_metrics', 'mta_toolbox_audio', 'mta_toolbox_server',
         'mta_filecenter_audio', 'mta_filecenter_storage', 'mta_filecenter_companion')
HELPERS = ('need', 'path_identity', 'actor_snapshot', 'client_for', 'wire', 'request', 'close_phase')
PHASES = ('mother_row_parent', 'row_parent', 'row_handler', 'table_open_handler',
          'table_query_handler', 'close_row', 'range_error')
RESULT_PREFIX = b'FILECENTER_MEDIA_LOCK_DEADLINE_V1='
FIXED_RESULT = {
    'schema': 'p011-filecenter-media-lock-deadline-v1-host', 'passed': True,
    'two_variants': ('send', 'receive'), 'source_count': 18,
    'actual_family_modules': 9, 'old_methods': 0, 'total_phases': 14,
    'phase_order': PHASES, 'actual_http_connections': 42,
    'real_http': True, 'real_sockets': True, 'real_threads': True,
    'actual_linux_storage': True, 'original_clocks': True,
    'original_method_bodies_loaded': True, 'mother_row_alive_past_parent': True,
    'candidate_row_parent_bound': True, 'candidate_row_handler_bound': True,
    'candidate_table_open_handler_bound': True, 'candidate_table_query_handler_bound': True,
    'same_media_two_range_contention': True, 'fixture_holder_not_released_by_candidate': True,
    'close_interrupts_waiting_handlers': True, 'invalid_range_then_valid_range': True,
    'acquired_guard_error_releases_lock': True, 'error_exit_releases_lock': True,
    'short_setup_only_explicit_fixture': True, 'handler_cap_shorter_than_parent': True,
    'parent_cap_seconds': 1.25, 'handler_cap_seconds': 0.50,
    'parent_observation_margin_seconds': 0.20, 'scheduling_margin_seconds': 0.35,
    'cleanup_cap_seconds': 3.0, 'original_close_methods': True,
    'all_clients_closed': True, 'all_http_actors_closed': True,
    'all_serve_threads_joined': True, 'all_media_and_storage_handles_closed': True,
    'controlled_temp_trees_removed': True, 'namespace_restored': True,
    'source_preserved': True, 'complete_byte_inverse': True, 'complete_ast_inverse': True,
    'private_companion_root_guard_fixture': True, 'native_owner_admission_verified': False,
    'media_mutex_only_host_verified': True, 'full_filecenter_deadline_verified': False,
    'audio_source_fd_shorter_callback_deadline_verified': False,
    'blocking_file_io_preemption_verified': False,
    'prior_http_18_cases_replayed': False, 'prior_audio_or_tls_cases_replayed': False,
    'captured_mother_media_lock_verified': False, 'audio_child_started': False,
    'clock_fake': False, 'network_fake': False, 'storage_fake': False,
    'actual_p011': False, 'phone': False, 'rf': False, 'ui': False,
    'staging': False, 'graph_changed': False, 'full_network_restore_verified': False,
}


def need(value, code):
    if value is not True: raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pure_functions(raw, path, names, globals_):
    tree = ast.parse(raw.decode('utf-8'))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need(len(selected) == len(names) and {node.name for node in selected} == set(names), 'pure_function_inventory')
    module = types.ModuleType('_media_lock_pure_helpers')
    module.__dict__.update(globals_)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(BASE / path), 'exec'), module.__dict__)
    return module


def source_contract(rows):
    # Only pinned imports/constants and the pure recipe functions. Never old main/write.
    tree = ast.parse(rows[GENERATOR].decode('utf-8'))
    names = {'need', 'digest', 'definition_bytes', 'derive', 'prepare'}
    selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
                (isinstance(node, ast.FunctionDef) and node.name in names)]
    need({node.name for node in selected if isinstance(node, ast.FunctionDef)} == names,
         'recipe_pure_functions')
    recipe = types.ModuleType('_media_lock_recipe')
    recipe.__file__ = str(BASE / GENERATOR)
    exec(compile(ast.Module(body=selected, type_ignores=[]), recipe.__file__, 'exec'), recipe.__dict__)
    outputs, facts, inputs = recipe.prepare()
    need(type(outputs) is dict and len(outputs) == 4 and all(rows[key] == raw for key, raw in outputs.items()),
         'actual_generated_outputs_exact')
    need(type(inputs) is dict and len(inputs) == 2 and all(rows[key] == raw for key, raw in inputs.items()),
         'actual_recipe_inputs_exact')
    need(facts['complete_byte_inverse'] is True and facts['complete_ast_inverse'] is True and
         facts['all_other_definition_bytes_unchanged'] is True and facts['close_policy_unchanged'] is True and
         facts['original_75_role_graph_unchanged'] is True and facts['source_graph_integrated'] is False and
         facts['blocking_file_io_preemption_verified'] is False, 'recipe_boundaries')
    # Historical literal facts are read, not back-filled from this new check.
    donor_tree = ast.parse(rows[DONOR].decode('utf-8'))
    literal = [node for node in donor_tree.body if isinstance(node, ast.Assign) and
               any(isinstance(target, ast.Name) and target.id == 'FIXED_RESULT' for target in node.targets)]
    need(len(literal) == 1, 'mother_result_literal')
    original = ast.literal_eval(literal[0].value)
    need(original['media_lock_deadline_verified'] is False and
         original['blocking_filesystem_deadline_verified'] is False, 'mother_coverage_unchanged')
    return facts


def pinned_rows():
    rows = {}
    for key, size, digest in SOURCE_PINS:
        raw = (BASE / key).read_bytes()
        need((len(raw), sha(raw)) == (size, digest), 'worker_fixed_input_pin')
        rows[key] = raw
    return rows


@contextmanager
def family(rows, branch, candidate):
    need(branch in ('send', 'receive') and type(candidate) is bool, 'family_selector')
    need(not any(name in sys.modules for name in NAMES), 'family_namespace_busy')
    indices = list(range(7)) + ([7, 9] if branch == 'send' else [8, 10])
    if candidate: indices[8] = 11 if branch == 'send' else 12
    modules = {}
    try:
        for name, index in zip(NAMES, indices):
            path = SOURCE_PINS[index][0]
            module = types.ModuleType(name)
            module.__file__ = str(BASE / path)
            modules[name] = module
            sys.modules[name] = module
            exec(compile(rows[path], module.__file__, 'exec'), module.__dict__)
        yield modules
    finally:
        need(all(sys.modules.get(name) is module for name, module in modules.items()), 'family_identity_changed')
        for name, module in reversed(tuple(modules.items())): del sys.modules[name]
        need(not any(name in sys.modules for name in NAMES), 'family_namespace_not_restored')


def wait_until(until):
    while time.monotonic() < until:
        time.sleep(min(0.005, max(0.0, until - time.monotonic())))


def range_wire(helper, value, path, ranged='bytes=0-15'):
    data = helper.wire(value, path)
    need(data.endswith(b'\r\n\r\n'), 'wire_complete')
    return data[:-2] + b'Range: ' + ranged.encode('ascii') + b'\r\n\r\n'


def recv_response(client, until):
    data = b''
    while True:
        remaining = until - time.monotonic()
        need(remaining > 0.0, 'focused_http_response_deadline')
        client.settimeout(remaining)
        block = client.recv(4096)
        if not block: break
        data += block
        need(len(data) <= 32768, 'focused_http_response_budget')
    need(b'\r\n\r\n' in data, 'focused_http_response_headers')
    return data.split(b'\r\n\r\n', 1)


def assert_lock_available(lock):
    # A different real thread must acquire it: same-thread RLock reentry is no proof.
    result = []
    def probe():
        acquired = lock.acquire(False)
        try: result.append(acquired is True)
        finally:
            if acquired: lock.release()
    worker = threading.Thread(target=probe)
    worker.start(); worker.join(0.5)
    need(not worker.is_alive() and result == [True], 'actual_mutex_not_released')


def blocked_handler(row, module, value, lock, phase, candidate):
    worker = row.get('thread')
    if type(worker) is not threading.Thread or not worker.is_alive(): return None
    frame = sys._current_frames().get(worker.ident)
    handler = None
    method = (module._Companion.open_file if phase == 'table_open_handler' else
              module._Companion.media_row if phase == 'table_query_handler' else module._FileCenterHandler.media)
    seen_method = seen_lock = False
    while frame is not None:
        original = frame.f_locals.get('self')
        if frame.f_code is method.__code__: seen_method = True
        if isinstance(original, module._FileCenterHandler) and original.server.companion is value:
            handler = original
        if candidate and frame.f_code is module._MediaLock.__enter__.__code__:
            seen_lock = type(original) is module._MediaLock and original.companion is value and original.lock is lock
        if not candidate and frame.f_code is method.__code__:
            # Mother is blocked at its unchanged with-row-lock statement, not a new fixture method.
            source = Path(method.__code__.co_filename).read_bytes()
            tree = ast.parse(source.decode('utf-8'))
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_FileCenterHandler']
            methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == 'media']
            waits = [node for node in ast.walk(methods[0]) if isinstance(node, ast.With)]
            seen_lock = len(waits) == 1 and frame.f_lineno == waits[0].lineno
        frame = frame.f_back
    return handler if seen_method and seen_lock else None


def wait_blocked(helper, module, value, lock, phase, candidate, until):
    while time.monotonic() < until:
        rows = helper.actor_snapshot(value)
        active = [row for row in rows if row.get('entered') is True and row.get('ended') is False and
                  row.get('start_returned') is True and row.get('thread') is not None and row['thread'].is_alive()]
        if len(active) == 2:
            handlers = [blocked_handler(row, module, value, lock, phase, candidate) for row in active]
            if all(handler is not None for handler in handlers):
                for row, handler in zip(active, handlers):
                    need(row['request'] is row['request_original'] and row['thread'] is row['thread_original'] and
                         row['error'] is None and handler.request is row['request_original'], 'retained_http_actor_identity')
                    need(handler.wfile.deadline is handler.deadline and handler.deadline <= value.until,
                         'original_handler_output_cap')
                return tuple(active), tuple(handlers)
        time.sleep(0.005)
    raise ValueError('two_actual_http_mutex_waiters_not_observed')


def require_ended(rows, until):
    for row in rows:
        row['thread_original'].join(max(0.0, until - time.monotonic()))
    need(all(row['ended'] is True and not row['thread_original'].is_alive() and
             row['request_original'].fileno() == -1 and row['request'] is row['request_original'] and
             row['thread'] is row['thread_original'] for row in rows), 'actual_http_waiter_not_ended')


def run_phase(helper, modules, candidate, phase):
    started = time.monotonic()
    root = tempfile.mkdtemp(prefix='p011-fc-media-lock-v1-')
    identity = helper.path_identity(root)
    clients, value = [], None
    lock, held = None, False
    try:
        need(os.path.realpath(root) == root, 'synthetic_root_realpath')
        received = os.path.join(root, 'Received')
        os.mkdir(received, 0o700)
        media = b'\x5a' * 1024
        with open(os.path.join(received, 'media.mp4'), 'xb') as target:
            need(target.write(media) == len(media), 'synthetic_media_short_write')
        module = modules['mta_filecenter_companion']
        cap = float(time.monotonic() + (1.25 if phase in ('mother_row_parent', 'row_parent') else 5.0))
        value = module._Companion.__new__(module._Companion)
        module._Companion.__init__(value, root, cap, lambda: True)
        need(value.until is cap and value.audio.parent_until is cap and
             value.audio._parent_until_original is cap and value.state.store.fd_mode is True and
             value.owner is None, 'explicit_private_binding_fixture')
        opened = helper.request(value, clients, modules['mta_toolbox_json'], '/api/open?path=Received/media.mp4')
        need(type(opened) is dict and opened['kind'] == 'video' and opened['bytes'] == 1024 and
             len(value.media) == 1 and value.media[0]['handle'].closed is False, 'actual_media_open')
        path = '/api/media?cap=' + value.media[0]['cap']
        row = value.media[0]
        if phase == 'range_error':
            bad = helper.client_for(value, clients)
            bad.sendall(range_wire(helper, value, path, 'bytes=1024-1025'))
            head, unused = recv_response(bad, min(cap, time.monotonic() + 1.0))
            need(head.split(b'\r\n', 1)[0] == b'HTTP/1.0 400 Bad Request', 'invalid_range_original_status')
            bad.close()
            assert_lock_available(row['lock'])
            good = helper.client_for(value, clients)
            good.sendall(range_wire(helper, value, path))
            head, body = recv_response(good, min(cap, time.monotonic() + 1.0))
            need(head.split(b'\r\n', 1)[0].startswith(b'HTTP/1.0 206 ') and body == media[:16],
                 'valid_range_after_error')
            good.close()
            assert_lock_available(row['lock'])
            # Original guard is an explicitly labelled fixture; only its held-lock result changes.
            original_guard, observed = value.guard, []
            def guard():
                owned = row['lock']._is_owned()
                observed.append(owned)
                return not owned
            value.guard = guard
            try:
                try:
                    with module._MediaLock(value, row['lock'], cap):
                        raise AssertionError('post_acquire_guard_should_reject')
                except ValueError as error:
                    need(str(error) == 'filecenter_session_ended', 'original_guard_error')
                need(observed == [False, True], 'actual_post_acquire_guard_fixture')
            finally: value.guard = original_guard
            assert_lock_available(row['lock'])
            return float(time.monotonic() - started)
        lock = value.media_lock if phase.startswith('table_') else row['lock']
        need(lock.acquire(False) is True and lock._is_owned(), 'fixture_original_lock_not_owned')
        held = True
        short = phase.endswith('_handler')
        handler_until = float(time.monotonic() + 0.50) if short else cap
        if short:
            original = module._FileCenterHandler
            class ShortHandler(original):
                # Only original setup's input cap is shortened; all business methods are inherited.
                def setup(self):
                    self.deadline = min(self.deadline, handler_until)
                    original.setup(self)
            need(ShortHandler.media is original.media and ShortHandler.dispatch is original.dispatch,
                 'short_fixture_business_methods_unchanged')
            value.server.handler = ShortHandler
            need(handler_until + 1.0 < cap, 'handler_fixture_not_shorter_than_parent')
        for unused in range(2):
            client = helper.client_for(value, clients)
            data = (helper.wire(value, '/api/open?path=Received/media.mp4') if phase == 'table_open_handler'
                    else range_wire(helper, value, path))
            client.sendall(data)
        rows, handlers = wait_blocked(helper, module, value, lock, phase, candidate,
                                     min(cap, handler_until) - 0.05)
        if short:
            need(all(handler.deadline == handler_until and handler.deadline < cap for handler in handlers),
                 'actual_short_handler_cap_not_forwarded')
        if phase == 'mother_row_parent':
            wait_until(cap + 0.20)
            need(all(row['ended'] is False and row['thread_original'].is_alive() for row in rows),
                 'mother_mutex_counterexample_not_observed')
        elif phase == 'close_row':
            need(value.close(cleanup_until=float(time.monotonic() + 1.0)) is True and value.closed() is True,
                 'original_close_waiting_mutex_incomplete')
            require_ended(rows, time.monotonic())
        else:
            require_ended(rows, min(cap, handler_until) + 0.35)
            if short: need(time.monotonic() < cap, 'short_handler_waited_for_parent')
        # Candidate owns only its acquired locks; it must never unlock the fixture holder.
        need(lock._is_owned(), 'fixture_holder_released_by_candidate')
        return float(time.monotonic() - started)
    finally:
        # Only the fixture owner releases this held RLock, before original resource cleanup.
        if held:
            need(lock._is_owned(), 'fixture_lock_owner_changed_at_cleanup')
            lock.release()
        helper.close_phase(value, clients, root, identity)


def worker():
    need(sys.platform.startswith('linux') and threading.current_thread() is threading.main_thread(),
         'actual_linux_worker_only')
    rows = pinned_rows()
    source_contract(rows)
    helper = pure_functions(rows[DONOR], DONOR, HELPERS,
        dict(os=os, stat=stat, socket=socket, threading=threading, time=time, shutil=shutil, json=json))
    durations = []
    for branch in ('send', 'receive'):
        with family(rows, branch, False) as modules:
            durations.append(run_phase(helper, modules, False, PHASES[0]))
        with family(rows, branch, True) as modules:
            for phase in PHASES[1:]: durations.append(run_phase(helper, modules, True, phase))
    need(len(durations) == 14 and pinned_rows() == rows, 'worker_sources_or_phase_count_changed')
    result = dict(FIXED_RESULT)
    result['durations'] = tuple(durations)
    print(RESULT_PREFIX.decode('ascii') + repr(result))
    return 0


def run(execute):
    raw = (BASE / SEALER[0]).read_bytes()
    need((len(raw), sha(raw)) == SEALER[1:], 'sealer_pin')
    seal = types.ModuleType('_filecenter_media_lock_sealer')
    seal.__file__ = str(BASE / SEALER[0])
    exec(compile(raw, seal.__file__, 'exec'), seal.__dict__)
    mode = 'host' if execute else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('filecenter-media-lock-deadline-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {SEALER[0]: raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='filecenter-media-lock-deadline-v1-parent', mode=mode, passed=False,
        error=None, child_invocations=0, child_exit=None, timed_out=False, input_count=1,
        source_preserved=False, snapshot_preserved=False, observation=None,
        narrow_source_delta_verified=False, actual_p011=False, phone=False, rf=False, ui=False,
        native_owner=False, graph_changed=False, staging=False, full_restore_verified=False,
        audio_source_fd_shorter_callback_deadline_verified=False,
        blocking_file_io_preemption_verified=False, full_filecenter_deadline_verified=False,
        captured_mother_media_lock_verified=False, old_methods_run=0)
    snapshotted = False
    try:
        for key, size, digest in SOURCE_PINS:
            evidence.read(BASE / key, key=key, pin=(size, digest))
            if key.endswith('.py'):
                ast.parse(inputs[key].decode('utf-8'), feature_version=(3, 5))
        source_contract(inputs)
        report['narrow_source_delta_verified'] = True
        validator = pure_functions(inputs[PARENT], PARENT, ('need', 'validate'), dict(math=math))
        for key in (SELF, CMD): evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        snapshotted = True
        need(str(BASE) == r'D:\project\P011\working\MtaP011-v0.1', 'fixed_workspace')
        script = str(out / 'private-inputs' / SELF)
        need(script.startswith(str(BASE / 'results') + '\\') and script[:3].lower() == 'd:\\', 'snapshot_entry_path')
        linux_script = '/mnt/d/' + script[3:].replace('\\', '/')
        bootstrap = ('import runpy,signal,sys;signal.alarm(50);'
                     'sys.argv=[sys.argv[1],sys.argv[2]];'
                     'runpy.run_path(sys.argv[0],run_name="__main__")')
        argv = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3', '-I', '-B', '-c',
                bootstrap, linux_script, '--worker']
        seal.fresh(out / 'private-raw/argv.json', (json.dumps(argv) + '\n').encode('ascii'))
        report.update(input_count=len(inputs), affected_phases=14, child_alarm_seconds=50,
                      child_host_timeout_seconds=60, alarm_before_entry=True)
        if execute:
            report['child_invocations'] = 1
            try:
                child = subprocess.run(argv, cwd=str(out / 'private-inputs'), capture_output=True, timeout=60)
                code, stdout, stderr = child.returncode, child.stdout, child.stderr
            except subprocess.TimeoutExpired as error:
                report['timed_out'] = True
                code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
            for name, data in (('stdout', stdout), ('stderr', stderr)):
                seal.fresh(out / ('private-raw/child.' + name + '.raw'), data)
            seal.fresh(out / 'private-raw/child.host-exit', (str(code) + '\n').encode('ascii'))
            report['child_exit'] = code
            need(report['timed_out'] is False and type(code) is int and code == 0, 'child_failed')
            lines = stdout.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n').splitlines()
            need(len(lines) == 1 and lines[0].startswith(RESULT_PREFIX) and len(lines[0]) <= 16384,
                 'single_worker_result_marker')
            result = ast.literal_eval(lines[0][len(RESULT_PREFIX):].decode('ascii'))
            validator.validate(result, dict(FIXED_RESULT=FIXED_RESULT))
            need(stderr == b'', 'worker_stderr_not_empty')
            report['observation'] = result
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)[:180]
        seal.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            if not snapshotted: evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['source_preserved'] = all((BASE / key).read_bytes() == raw for key, raw in inputs.items())
            report['snapshot_preserved'] = all((out / 'private-inputs' / key).read_bytes() == raw for key, raw in inputs.items())
            need(report['source_preserved'] and report['snapshot_preserved'], 'inputs_changed')
        except BaseException as error:
            report['passed'] = False
            report['error'] = report['error'] or type(error).__name__ + ':' + str(error)[:180]
            seal.fresh(out / 'private-raw/preservation-exception.txt', traceback.format_exc().encode('utf-8'))
    readme = (b'Default SOURCE; --run invokes one focused WSL Linux worker, not old tests/main.\n'
              b'Both actual FC9 families; same-media mutex, parent/request cap, close and error release.\n'
              b'Private Companion/root/guard and shorter setup are explicit fixtures, not native Owner.\n'
              b'No audio callback 4s, blocking filesystem preemption, device, RF, phone or graph claim.\n'
              b'Historical false coverage remains false. Raw streams, exits and snapshots stay private.\n')
    result = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=result['report']['passed'], output=str(out),
        archive=str(result['archive']) if result['archive'] else None,
        archive_sha256=result['archive_sha256'], error=result['report']['error']), ensure_ascii=True))
    return result['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--run', action='store_true')
    group.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    raise SystemExit(worker() if arguments.worker else run(arguments.run))
