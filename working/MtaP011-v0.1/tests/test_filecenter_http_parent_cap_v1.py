"""One new Linux real-HTTP parent-cap contrast; no old test invocation.

Both actual FC9 dependency families are loaded unchanged except the two
explicitly inverted HTTP/Companion changes. Private Companion root/guard
construction is a labelled fixture, not formal Owner admission. Real clocks,
TCP sockets, HTTP actors, Linux storage and original cleanup methods run.
No audio child, UI, radio, phone, graph, staging or restoration is exercised.
Only new, identity-checked synthetic trees may be removed after closure.
"""
import ast
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse


BASE = Path(__file__).resolve().parents[1]
SELECTOR = 'FileCenterHttpParentCapV1Tests.test_two_actual_families_http_parent_cap'
RESULT_PREFIX = b'FILECENTER_HTTP_PARENT_CAP_V1='
SOURCE_PINS = (
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069,
     'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py', 9303,
     '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
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
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_companion.py', 25966,
     '51f212ef07e0e323cc3803cfd2583ec29867ce0bbf7daff9129ad51d4f6eeeb3'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508,
     'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284'),
    ('candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py', 26088,
     '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f'),
    ('candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py', 33630,
     '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba'),
    ('candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
     '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'),
)
FIXED_RESULT = {
    'passed': True,
    'schema': 'p011-filecenter-http-parent-cap-v1-host',
    'two_variants': ('send', 'receive'), 'source_count': 14,
    'methods': 1, 'old_methods': 0, 'actual_family_modules': 9,
    'fault_order': ('headers', 'small_post', 'media_backpressure'),
    'mother_fault_phases': 4, 'candidate_fault_phases': 6, 'candidate_normal_phases': 2,
    'total_phases': 12, 'actual_http_connections': 18,
    'prior_cases_not_replayed': ('send:mother:headers', 'send:mother:small_post'),
    'prior_whole_failure_preserved': True,
    'real_http': True, 'real_socket': True, 'real_threads': True,
    'actual_linux_storage': True, 'original_clocks': True,
    'actual_blocked_recv_sendall_observed': True,
    'mother_actor_alive_past_parent': True, 'candidate_actor_ended_within_parent_margin': True,
    'parent_cap_seconds': 1.25, 'parent_observation_margin_seconds': 0.20,
    'scheduling_margin_seconds': 0.35, 'cleanup_cap_seconds': 3.0,
    'original_body_and_output_deadlines_inherit_candidate_parent': True,
    'normal_files_and_ui_event': True, 'original_close_methods': True,
    'all_clients_closed': True, 'all_http_actors_closed': True, 'all_serve_threads_joined': True,
    'original_media_and_storage_handles_closed': True, 'controlled_temp_trees_removed': True,
    'namespace_restored': True, 'complete_byte_inverse': True, 'source_preserved': True,
    'private_companion_root_guard_fixture': True, 'original_owner_admission_verified': False,
    'full_filecenter_owner_deadline_verified': False, 'media_lock_deadline_verified': False,
    'blocking_filesystem_deadline_verified': False,
    'network_fake': False, 'storage_fake': False, 'clock_fake': False,
    'audio_child_started': False, 'ui_started': False, 'rf': False, 'phone': False,
    'staging': False, 'graph_changed': False, 'full_network_restore_verified': False}
NAMES = ('mta_toolbox_json', 'mta_toolbox_minhttp', 'mta_toolbox_storage',
         'mta_toolbox_metrics', 'mta_toolbox_audio', 'mta_toolbox_server',
         'mta_filecenter_audio', 'mta_filecenter_storage', 'mta_filecenter_companion')
PARENT_SECONDS = 1.25
OBSERVATION_MARGIN = 0.20
SCHEDULING_MARGIN = 0.35
MEDIA_BYTES = 16 * 1024 * 1024
HANDLER_BEFORE = b'class _FileCenterHandler(Handler):\n'
HANDLER_AFTER = HANDLER_BEFORE + (
    b'    def setup(self):\n'
    b'        self.deadline = min(self.deadline, self.server.companion.until)\n'
    b'        Handler.setup(self)\n\n')
HEADER_BEFORE = b'        header_deadline = time.monotonic()+4\n'
HEADER_AFTER = b'        header_deadline = min(self.deadline, time.monotonic()+4)\n'
PRIOR_NOT_REPLAYED = (('send', False, 'headers'), ('send', False, 'small_post'))


def need(value, code):
    if value is not True:
        raise AssertionError(code)


def sources():
    rows = {}
    for path, size, digest in SOURCE_PINS:
        raw = (BASE / path).read_bytes()
        need((len(raw), hashlib.sha256(raw).hexdigest()) == (size, digest), 'fixed_source_pin')
        rows[path] = raw
    pairs = ((SOURCE_PINS[9][0], SOURCE_PINS[11][0], HANDLER_BEFORE, HANDLER_AFTER),
             (SOURCE_PINS[10][0], SOURCE_PINS[12][0], HANDLER_BEFORE, HANDLER_AFTER),
             (SOURCE_PINS[1][0], SOURCE_PINS[13][0], HEADER_BEFORE, HEADER_AFTER))
    for old_path, new_path, before, after in pairs:
        old, new = rows[old_path], rows[new_path]
        need(old.count(before) == 1 and old.count(after) == 0 and new.count(after) == 1,
             'exact_source_change_count')
        need(new == old.replace(before, after, 1) and new.replace(after, before, 1) == old,
             'complete_source_byte_inverse')
    return rows


@contextmanager
def family(rows, branch, candidate):
    need(branch in ('send', 'receive') and type(candidate) is bool, 'fixed_family_selector')
    need(not any(name in sys.modules for name in NAMES), 'canonical_family_namespace_busy')
    indices = list(range(7)) + ([7, 9] if branch == 'send' else [8, 10])
    if candidate:
        indices[1] = 13
        indices[8] = 11 if branch == 'send' else 12
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
        # Original objects only; never discard an unexpected foreign namespace.
        need(all(sys.modules.get(name) is module for name, module in modules.items()),
             'loaded_family_identity_changed')
        for name, module in reversed(tuple(modules.items())):
            del sys.modules[name]
        need(not any(name in sys.modules for name in NAMES), 'family_namespace_not_restored')


def path_identity(path):
    value = os.lstat(path)
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def until_wait(until):
    while time.monotonic() < until:
        time.sleep(min(0.01, max(0.0, until - time.monotonic())))


def actor_snapshot(value):
    with value.server.actor_lock:
        return tuple(value.server.actor_rows)


def call_line(raw, class_name, method_name, call_name):
    tree = ast.parse(raw.decode('utf-8'))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    need(len(classes) == 1, 'actual_http_class_unique')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == method_name]
    need(len(methods) == 1, 'actual_http_method_unique')
    calls = [node for node in ast.walk(methods[0]) if isinstance(node, ast.Call) and
             isinstance(node.func, ast.Attribute) and node.func.attr == call_name]
    need(len(calls) == 1, 'actual_http_blocking_call_unique')
    return calls[0].lineno


def blocked_handler(row, code, line, companion_type):
    worker = row.get('thread')
    if type(worker) is not threading.Thread or not worker.is_alive():
        return None
    frame = sys._current_frames().get(worker.ident)
    matched = False
    handler = None
    while frame is not None:
        if frame.f_code is code and frame.f_lineno == line:
            matched = True
        original = frame.f_locals.get('self')
        if type(original) is companion_type:
            handler = original
        frame = frame.f_back
    return handler if matched else None


def wait_actor(value, expected_count, code, line, handler_type):
    until = value.until - 0.25
    while time.monotonic() < until:
        rows = actor_snapshot(value)
        if len(rows) == expected_count:
            row = rows[-1]
            if row.get('entered') is True and row.get('start_returned') is True:
                handler = blocked_handler(row, code, line, handler_type)
                if handler is not None:
                    need(row['request'] is row['request_original'] and
                         row['thread'] is row['thread_original'] and row['error'] is None,
                         'original_http_actor_identity')
                    return row, handler
        time.sleep(0.005)
    raise AssertionError('real_http_blocking_call_not_observed')


def client_for(value, clients, receive_buffer=False):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clients.append(client)  # Own the exact socket before options/connect can fail.
    if receive_buffer:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        need(client.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) <= 16384,
             'client_receive_buffer_not_small')
    client.settimeout(min(0.5, max(0.001, value.until - time.monotonic())))
    client.connect(value.address)
    return client


def wire(value, path, body=None, complete_headers=True):
    method = 'POST' if body is not None else 'GET'
    data = (method + ' ' + path + ' HTTP/1.0\r\nHost: ' + value.server.expected_host +
            '\r\nX-P011-Token: ' + value.state.token + '\r\n').encode('ascii')
    if body is not None:
        data += ('Content-Length: %d\r\n' % len(body)).encode('ascii')
    return data + (b'\r\n' if complete_headers else b'')


def request(value, clients, codec, path, body=None):
    client = client_for(value, clients)
    try:
        client.sendall(wire(value, path, body) + (body or b''))
        data = b''
        end = min(value.until, time.monotonic() + 2.0)
        while True:
            remaining = end - time.monotonic()
            need(remaining > 0, 'normal_http_response_deadline')
            client.settimeout(remaining)
            block = client.recv(4096)
            if not block:
                break
            data += block
            need(len(data) <= 32768, 'normal_http_response_budget')
        need(b'\r\n\r\n' in data, 'normal_http_response_headers')
        head, content = data.split(b'\r\n\r\n', 1)
        need(head.split(b'\r\n', 1)[0] == b'HTTP/1.0 200 OK', 'normal_http_response_status')
        # The product's 3069-byte JSON encoder intentionally has no loads.
        # Decode the actual bounded HOST HTTP response with HOST stdlib JSON.
        parsed = json.loads(content.decode('utf-8'))
        need(type(parsed) is dict and parsed.get('ok') is True and 'data' in parsed,
             'normal_http_response_envelope')
        return parsed['data']
    finally:
        client.close()
        need(client.fileno() == -1, 'normal_client_not_closed')


def close_phase(value, clients, root, identity):
    client_failures = []
    for client in reversed(clients):
        try:
            client.close()
            need(client.fileno() == -1, 'client_socket_close_unknown')
        except BaseException as error:
            client_failures.append(error)
    closed = False
    if value is not None:
        # Do not replace or renew the original Companion closing method.
        closed = value.close(cleanup_until=float(time.monotonic() + 3.0)) is True
        need(closed and value.closed() is True, 'original_companion_close_incomplete')
        value.thread.join(0.0)
        need(not value.thread.is_alive() and value.server.actors_closed() is True,
             'original_http_threads_not_closed')
        need(all(row['ended'] is True and row['request_original'].fileno() == -1 and
                 row['thread'] is not None and not row['thread'].is_alive()
                 for row in actor_snapshot(value)), 'original_http_actor_not_closed')
        need(value.audio.actors_closed() is True and not value.audio.tickets and
             value.state.store.rootfd is None and value.state.store.opens_closed() is True and
             all(row['closed'] and row['handle'].closed for row in value.media),
             'original_media_storage_or_audio_not_closed')
    need(not client_failures and all(client.fileno() == -1 for client in clients),
         'original_clients_not_closed')
    need(value is None or closed, 'unknown_original_resources_retained')
    need(os.path.isabs(root) and os.path.realpath(root) == root and
         path_identity(root) == identity and stat.S_ISDIR(identity[2]) and
         stat.S_IMODE(identity[2]) == 0o700, 'synthetic_root_identity_changed')
    shutil.rmtree(root)  # Only this fresh exact identity, after all actors/handles closed.
    need(not os.path.lexists(root), 'synthetic_root_not_removed')


def run_phase(modules, source_rows, branch, candidate, phase):
    started = time.monotonic()
    root = tempfile.mkdtemp(prefix='p011-fc-http-parent-cap-')
    identity = path_identity(root)
    value = None
    clients = []
    try:
        need(os.path.realpath(root) == root, 'synthetic_root_realpath')
        received = os.path.join(root, 'Received')
        os.mkdir(received, 0o700)
        if phase == 'media_backpressure':
            with open(os.path.join(received, 'media.mp4'), 'xb') as target:
                block = b'\x5a' * 65536
                for unused in range(MEDIA_BYTES // len(block)):
                    need(target.write(block) == len(block), 'synthetic_media_short_write')
        elif phase == 'normal':
            with open(os.path.join(received, 'probe.txt'), 'xb') as target:
                need(target.write(b'HTTP parent cap\n') == 16, 'synthetic_text_short_write')
        companion = modules['mta_filecenter_companion']
        http = modules['mta_toolbox_minhttp']
        codec = modules['mta_toolbox_json']
        cap = float(time.monotonic() + (3.0 if phase == 'normal' else PARENT_SECONDS))
        value = companion._Companion.__new__(companion._Companion)
        companion._Companion.__init__(value, root, cap, lambda: True)
        need(value.until is cap and value.audio.parent_until is cap and
             value.audio._parent_until_original is cap and value.state.store.fd_mode is True,
             'original_private_companion_cap_binding')
        if phase == 'normal':
            listing = request(value, clients, codec, '/api/files?path=Received')
            need(type(listing) is dict and type(listing.get('entries')) is list and
                 len(listing['entries']) == 1 and listing['entries'][0]['path'] == 'Received/probe.txt' and
                 listing['entries'][0]['kind'] == 'text' and listing['entries'][0]['bytes'] == 16,
                 'normal_files_request_not_preserved')
            event = request(value, clients, codec, '/api/ui/event', b'event=page_Files')
            need(type(event) is dict and event.get('recorded') is True and
                 len(value.state.events) == 1 and value.state.events[0]['event'] == 'page_Files',
                 'normal_ui_event_not_preserved')
        else:
            need(cap - time.monotonic() >= 0.8, 'phase_preparation_not_within_original_cap')
            expected = 1
            if phase == 'media_backpressure':
                opened = request(value, clients, codec, '/api/open?path=Received/media.mp4')
                need(type(opened) is dict and opened.get('kind') == 'video' and
                     opened.get('bytes') == MEDIA_BYTES and type(opened.get('url')) is str,
                     'original_media_open_not_preserved')
                location = urllib.parse.urlsplit(opened['url'])
                need(location.hostname == '127.0.0.1' and location.port == value.address[1],
                     'original_media_endpoint_not_loopback')
                path = location.path + '?' + location.query
                client = client_for(value, clients, receive_buffer=True)
                client.sendall(wire(value, path))
                code = http.SocketOutput.write.__code__
                line = call_line(source_rows, 'SocketOutput', 'write', 'sendall')
                expected = 2
            elif phase == 'headers':
                client = client_for(value, clients)
                client.sendall(wire(value, '/api/files', complete_headers=False))
                code = http.BaseHTTPRequestHandler.handle.__code__
                line = call_line(source_rows, 'BaseHTTPRequestHandler', 'handle', 'recv')
            else:
                need(phase == 'small_post', 'fixed_http_fault_phase')
                client = client_for(value, clients)
                client.sendall(wire(value, '/api/ui/event', b'event=page_Files'))
                code = http.BodyStream.read.__code__
                line = call_line(source_rows, 'BodyStream', 'read', 'recv')
            row, handler = wait_actor(value, expected, code, line, companion._FileCenterHandler)
            need(handler.request is row['request_original'] and handler.server is value.server and
                 handler.wfile.deadline is handler.deadline, 'original_handler_output_identity')
            if candidate:
                need(handler.deadline is cap, 'candidate_http_parent_cap_not_inherited')
                if phase == 'small_post':
                    need(handler.rfile.deadline is cap, 'candidate_post_parent_cap_not_inherited')
                end = cap + SCHEDULING_MARGIN
                while time.monotonic() < end and row['thread'].is_alive():
                    time.sleep(0.005)
                need(not row['thread'].is_alive() and row['ended'] is True and
                     row['request_original'].fileno() == -1,
                     'candidate_http_actor_exceeded_parent_margin')
            else:
                need(handler.deadline > cap + 100.0, 'mother_request_deadline_not_original')
                until_wait(cap + OBSERVATION_MARGIN)
                need(row['thread'].is_alive() and row['ended'] is False and
                     blocked_handler(row, code, line, companion._FileCenterHandler) is handler,
                     'mother_real_http_counterexample_not_observed')
    finally:
        close_phase(value, clients, root, identity)
    elapsed = float(time.monotonic() - started)
    need(math.isfinite(elapsed) and 0.0 <= elapsed <= 10.0, 'phase_elapsed_range')
    return elapsed


class FileCenterHttpParentCapV1Tests(unittest.TestCase):
    def test_two_actual_families_http_parent_cap(self):
        need(os.name == 'posix' and sys.platform.startswith('linux') and
             hasattr(sys, '_current_frames'), 'linux_real_http_target_required')
        original_sources = sources()
        durations = []
        for branch in ('send', 'receive'):
            for candidate in (False, True):
                with family(original_sources, branch, candidate) as modules:
                    http_path = SOURCE_PINS[13 if candidate else 1][0]
                    for phase in ('headers', 'small_post', 'media_backpressure'):
                        if (branch, candidate, phase) in PRIOR_NOT_REPLAYED:
                            continue
                        durations.append(run_phase(modules, original_sources[http_path],
                                                   branch, candidate, phase))
                    if candidate:
                        durations.append(run_phase(modules, original_sources[http_path],
                                                   branch, candidate, 'normal'))
        need(len(durations) == 12 and all(type(value) is float and math.isfinite(value) and
             0.0 <= value <= 10.0 for value in durations), 'complete_real_phase_durations')
        need(sources() == original_sources, 'source_bytes_changed_during_test')
        result = dict(FIXED_RESULT, durations=tuple(durations))
        print(RESULT_PREFIX.decode('ascii') + repr(result), flush=True)


if __name__ == '__main__':
    unittest.main()
