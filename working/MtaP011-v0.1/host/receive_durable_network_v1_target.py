"""PC-only maker for one finite P011 durable loopback network experiment.

Nothing in this module runs a target, a HOST fixture, a build or a device tool.
The caller supplies the ten fixed source byte strings. Seven runtime sources
are embedded completely unchanged; only the already-passed HOST test's real
filesystem operations and unavailable unittest/mock framework are adapted.
The original _LoopbackOwner class is extracted whole, not a fake transport.
The outer carrier must install alarm(80) before stdin read and use HOST 95s.
This target never changes that alarm, original 30+5 phase periods, or the
PreparedSend OpenSSL <=10s slice. Loopback consent is not native admission.
"""
import ast
import base64
import hashlib
import math
import zlib


PINS = (
    ('candidate/formal-receive-durable-state-v1/runtime/mta_storage.py', 56595,
     '365490e2dfe8a2c65d2b38fc8ae1a49747d09ed3b127677e9fe61e69866052d0'),
    ('candidate/formal-receive-durable-state-v1/runtime/mta_transport.py', 41435,
     '9b05ef49059e9b06536de32186e7de1cfd531461d3e096eb266d49f760069f8e'),
    ('runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('candidate/file-utf8-v67/runtime/mta_files.py', 10987,
     'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('runtime/mta_send_preparation.py', 28532,
     '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('runtime/mta_sender_pump.py', 33455,
     '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c'),
    ('tests/test_sender_pump.py', 34154,
     '7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7'),
    ('tests/test_receive_bound_integration.py', 13877,
     'd0790f870bf62848ccfcb6f8c4937dbd6961aae63c5d849179f84af2187798ee'),
    ('tests/test_receive_durable_network_v1.py', 27020,
     '27d3dfb98857cf080a887fca8564e6b3e2dfb125c1752597fca7e5a7628f7124'),
)
RUNTIME_BYTES = 197023
TARGET_LIMIT = 2 * 1024 * 1024
MAX_LINE = 256
OUTPUT_LIMIT = 65536
RESULT_SCHEMA = 'p011-receive-durable-network-v1-device'
RESULT_PREFIX = b'P011_DURABLE_NETWORK='
RESULT_FIXED = {
    'schema': 'p011-receive-durable-network-v1-device',
    'passed': True,
    'methods': 1,
    'old_methods': 0,
    'phases': 2,
    'phase_order': ('late_cancel', 'ack_loss'),
    'files_per_phase': (2, 2),
    'bytes_per_phase': (274144, 274144),
    'tls_connections_per_phase': (2, 2),
    'actual_tls_connections': 4,
    'source_count': 10,
    'runtime_source_count': 7,
    'runtime_source_bytes': 197023,
    'python_version': (3, 5, 5),
    'machine': 'armv7l',
    'effective_uid': 0,
    'actual_loopback_tcp_tls_http': True,
    'actual_linux_storage': True,
    'original_archive_handle': True,
    'same_task_durable_fact': True,
    'durable_identity_retained': True,
    'late_cancel_original_failure': True,
    'late_cancel_success': False,
    'ack_original_stream_eof': True,
    'ack_traceback_bound': True,
    'ack_unsent_original_queue': True,
    'peer_ack_verified': False,
    'sender_completed': False,
    'saved_hashes_verified': True,
    'resources_closed': True,
    'threads_joined': True,
    'callers_exited': True,
    'constructor_loopback_admission_fixture': True,
    'target_socket_owner_fixture': True,
    'constructor_projection_restored': True,
    'observer_delegates_original': True,
    'observer_restored': True,
    'embedded_runtime_verified': True,
    'test_framework_adapted': True,
    'filesystem_utf8_explicit': True,
    'openssl_pin_verified': True,
    'openssl_descriptor_closed': True,
    'controlled_temp_tree_removed': True,
    'network_fake': False,
    'storage_fake': False,
    'clock_fake': False,
    'native_admission_verified': False,
    'full_executor_bridge_tested': False,
    'device_tested': True,
    'phone_tested': False,
    'rf_requested': False,
    'full_restore_verified': False,
}
RESULT_FIELDS = (
    'schema', 'passed', 'methods', 'old_methods', 'phases', 'phase_order',
    'files_per_phase', 'bytes_per_phase', 'tls_connections_per_phase',
    'actual_tls_connections', 'source_count', 'runtime_source_count',
    'runtime_source_bytes', 'python_version', 'machine', 'effective_uid',
    'actual_loopback_tcp_tls_http',
    'actual_linux_storage', 'original_archive_handle', 'same_task_durable_fact',
    'durable_identity_retained', 'late_cancel_original_failure',
    'late_cancel_success', 'ack_original_stream_eof', 'ack_traceback_bound',
    'ack_unsent_original_queue', 'peer_ack_verified', 'sender_completed',
    'saved_hashes_verified', 'resources_closed', 'threads_joined',
    'callers_exited', 'constructor_loopback_admission_fixture',
    'target_socket_owner_fixture', 'constructor_projection_restored',
    'observer_delegates_original', 'observer_restored',
    'embedded_runtime_verified', 'test_framework_adapted',
    'filesystem_utf8_explicit', 'openssl_pin_verified',
    'openssl_descriptor_closed', 'controlled_temp_tree_removed',
    'network_fake', 'storage_fake', 'clock_fake', 'native_admission_verified',
    'full_executor_bridge_tested', 'device_tested', 'phone_tested',
    'rf_requested', 'full_restore_verified', 'phase_elapsed_seconds',
)


def source_inputs():
    return PINS


def _fail(code):
    raise ValueError(code)


def _fixed_inputs(inputraws):
    if type(inputraws) is not dict or set(inputraws) != set(row[0] for row in PINS):
        _fail('target_input_keys')
    for path, size, digest in PINS:
        raw = inputraws[path]
        if type(raw) is not bytes or (len(raw), hashlib.sha256(raw).hexdigest()) != (size, digest):
            _fail('target_input_identity')
    if sum(row[1] for row in PINS[:7]) != RUNTIME_BYTES:
        _fail('runtime_total')
    return inputraws


def _source_node(raw, node):
    lines = raw.decode('utf-8').splitlines(keepends=True)
    if type(node.end_lineno) is not int or node.end_lineno < node.lineno:
        _fail('selected_source_range')
    return ''.join(lines[node.lineno - 1:node.end_lineno])


def _select(inputs):
    owner_raw = inputs[PINS[7][0]]
    owner_tree = ast.parse(owner_raw.decode('utf-8'))
    owners = [row for row in owner_tree.body
              if isinstance(row, ast.ClassDef) and row.name == '_LoopbackOwner']
    host_raw = inputs[PINS[9][0]]
    host_tree = ast.parse(host_raw.decode('utf-8'))
    classes = [row for row in host_tree.body
               if isinstance(row, ast.ClassDef) and row.name == 'ReceiveDurableNetworkV1Tests']
    if len(owners) != 1 or len(classes) != 1:
        _fail('selected_class_unique')
    phases = [row for row in classes[0].body
              if isinstance(row, ast.FunctionDef) and row.name == '_phase']
    methods = [row for row in classes[0].body
               if isinstance(row, ast.FunctionDef) and row.name.startswith('test_')]
    if len(phases) != 1 or len(methods) != 1:
        _fail('selected_phase_unique')
    return _source_node(owner_raw, owners[0]), _source_node(host_raw, phases[0])


def _adapt_phase(original):
    """Eight exact framework/filesystem blocks; reverse restores original bytes."""
    replacements = (
        (
            "        base = Path(tempfile.mkdtemp(prefix='mta-durable-network-host-'))\n"
            "        base_identity = os.lstat(base)\n"
            "        source, target, private = base / 'source', base / 'target', base / 'private'\n",
            "        temp_anchor = _temp_anchor()\n"
            "        base = tempfile.mkdtemp(prefix='mta-durable-network-device-', dir=TEMP_ROOT)\n"
            "        base_identity = os.lstat(native_name(base))\n"
            "        _owned_tree_current(base, base_identity, temp_anchor)\n"
            "        source, target, private = tuple(os.path.join(base, name)\n"
            "                                        for name in ('source', 'target', 'private'))\n",
        ),
        (
            "            (source / 'Text').mkdir(parents=True)\n"
            "            (source / 'GameResources').mkdir()\n"
            "            target.mkdir(mode=0o700)\n"
            "            private.mkdir(mode=0o700)\n",
            "            os.makedirs(native_name(os.path.join(source, 'Text')))\n"
            "            os.mkdir(native_name(os.path.join(source, 'GameResources')))\n"
            "            os.mkdir(native_name(target), 0o700)\n"
            "            os.mkdir(native_name(private), 0o700)\n",
        ),
        (
            "                (source / path).write_bytes(data)\n",
            "                _write_payload(os.path.join(source, path), data)\n",
        ),
        (
            "            with warnings.catch_warnings():\n"
            "                warnings.filterwarnings('ignore', message=r'ssl\\.PROTOCOL_TLSv1_2 is deprecated',\n"
            "                                        category=DeprecationWarning)\n"
            "                prepared.prepare()\n"
            "                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "                listener.set_inheritable(False)\n"
            "                listener.bind(('127.0.0.1', 0))\n"
            "                owner = owner_type(listener, until, cleanup_until)\n"
            "                pump = sender.SenderPump(listener, prepared.archive_handle, prepared.archive_size,\n"
            "                    prepared.file_count, prepared.total_bytes, prepared.request_payload,\n"
            "                    prepared.tls_context, owner, until)\n"
            "                # Constructor only. All subsequent connect/TLS/HTTP/IO is original.\n"
            "                with mock.patch.object(transport, 'private_ipv4', return_value='127.0.0.1') as allowance:\n"
            "                    receiver = transport.ReceiverTransport('127.0.0.1', listener.getsockname()[1],\n"
            "                        storage, cancelled=cancelled, absolute_until=until, clock=time.monotonic)\n"
            "                self.assertEqual(1, allowance.call_count)\n"
            "                self.assertIs(transport.private_ipv4, admission_original)\n",
            "            prepared.prepare()\n"
            "            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "            listener.set_inheritable(False)\n"
            "            listener.bind(('127.0.0.1', 0))\n"
            "            owner = owner_type(listener, until, cleanup_until)\n"
            "            pump = sender.SenderPump(listener, prepared.archive_handle, prepared.archive_size,\n"
            "                prepared.file_count, prepared.total_bytes, prepared.request_payload,\n"
            "                prepared.tls_context, owner, until)\n"
            "            admission_calls = []\n"
            "            def constructor_loopback(host):\n"
            "                self.assertEqual('127.0.0.1', host)\n"
            "                self.assertEqual([], admission_calls)\n"
            "                admission_calls.append(host)\n"
            "                return '127.0.0.1'\n"
            "            self.assertIs(transport.private_ipv4, admission_original)\n"
            "            transport.private_ipv4 = constructor_loopback\n"
            "            try:\n"
            "                receiver = transport.ReceiverTransport('127.0.0.1', listener.getsockname()[1],\n"
            "                    storage, cancelled=cancelled, absolute_until=until, clock=time.monotonic)\n"
            "            finally:\n"
            "                transport.private_ipv4 = admission_original\n"
            "            self.assertEqual(1, len(admission_calls))\n"
            "            self.assertIs(transport.private_ipv4, admission_original)\n",
        ),
        (
            "            expected_root = Path(binding.root)\n"
            "            result_root = Path(durable['directory'])\n"
            "            self.assertEqual(expected_root, result_root.parent)\n"
            "            self.assertTrue(result_root.name.startswith('received-'))\n",
            "            expected_root = _public_path(binding.root)\n"
            "            result_root = _public_path(durable['directory'])\n"
            "            self.assertEqual(expected_root, os.path.dirname(result_root))\n"
            "            self.assertTrue(os.path.basename(result_root).startswith('received-'))\n",
        ),
        (
            "                value = Path(path)\n"
            "                relative = value.relative_to(result_root).as_posix()\n"
            "                self.assertIn(relative, expected_keys)\n"
            "                self.assertFalse(value.is_symlink())\n"
            "                actual = value.read_bytes()\n",
            "                value = _public_path(path)\n"
            "                relative = _relative_member(value, result_root)\n"
            "                self.assertIn(relative, expected_keys)\n"
            "                self.assertFalse(os.path.islink(native_name(value)))\n"
            "                actual = _read_payload(value)\n",
        ),
        (
            "                    current = os.lstat(base)\n"
            "                    if ((current.st_dev, current.st_ino) != (base_identity.st_dev, base_identity.st_ino) or\n"
            "                            not base.is_absolute() or base.parent != Path(tempfile.gettempdir())):\n"
            "                        raise AssertionError('fresh test tree identity differs')\n"
            "                    # Only this exact identity-checked freshly-created HOST tree.\n"
            "                    shutil.rmtree(base)\n",
            "                    _owned_tree_current(base, base_identity, temp_anchor)\n"
            "                    # Only this identity-checked fresh tree under the fixed temp root.\n"
            "                    shutil.rmtree(native_name(base))\n",
        ),
        (
            "        self.assertFalse(base.exists())\n",
            "        self.assertFalse(os.path.lexists(native_name(base)))\n",
        ),
    )
    changed = original
    offsets = []
    for before, after in replacements:
        if changed.count(before) != 1 or after in changed:
            _fail('phase_exact_forward')
        offset = changed.index(before)
        changed = changed[:offset] + after + changed[offset + len(before):]
        offsets.append((offset, before, after))
    inverse = changed
    for offset, before, after in reversed(offsets):
        if inverse[offset:offset + len(after)] != after:
            _fail('phase_exact_reverse')
        inverse = inverse[:offset] + before + inverse[offset + len(after):]
    if inverse.encode('utf-8') != original.encode('utf-8'):
        _fail('phase_full_byte_inverse')
    tree = ast.parse('class TargetPhase:\n' + changed, feature_version=(3, 5))
    if len(tree.body) != 1 or len(tree.body[0].body) != 1:
        _fail('adapted_phase_shape')
    for bad in ('Path(', 'mock.', 'warnings.', 'unittest.'):
        if bad in changed:
            _fail('unavailable_target_framework')
    return changed


def _encoded(raw):
    value = base64.b64encode(zlib.compress(raw, 9))
    if zlib.decompress(base64.b64decode(value)) != raw:
        _fail('embedded_byte_roundtrip')
    return 'b"".join((\n' + ''.join('    %r,\n' % value[index:index + 128]
                                      for index in range(0, len(value), 128)) + '))'


TARGET_HELPERS = r'''# Target Python 3.5, actual original modules and real IO only.
import base64
import builtins
import errno
import hashlib
import io
import math
import os
import shutil
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
import types
import zlib

TEMP_ROOT = '/var/volatile/tmp'
OPENSSL_SHA = '387ef5932ebff2800640e0d47c4f353058abee2d4cf9d9644d5aa351f21b4d69'

def _reject(code):
    raise AssertionError(code)

class _Assertions(object):
    def assertEqual(self, left, right):
        if left != right: _reject('assert_equal')
    def assertNotEqual(self, left, right):
        if left == right: _reject('assert_not_equal')
    def assertIs(self, left, right):
        if left is not right: _reject('assert_identity')
    def assertIsNone(self, value):
        if value is not None: _reject('assert_none')
    def assertIsNotNone(self, value):
        if value is None: _reject('assert_not_none')
    def assertTrue(self, value, message='assert_true'):
        if not value: _reject(message)
    def assertFalse(self, value):
        if value: _reject('assert_false')
    def assertIn(self, value, values):
        if value not in values: _reject('assert_member')
    def assertNotIn(self, value, values):
        if value in values: _reject('assert_not_member')
    def assertGreater(self, left, right):
        if not left > right: _reject('assert_greater')
    def assertLess(self, left, right):
        if not left < right: _reject('assert_less')

def native_name(value):
    if type(value) is not str: _reject('native_public_type')
    return value.encode('utf-8')

def _public_path(value):
    if type(value) is not str or not value or '\x00' in value:
        _reject('public_path_type')
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        _reject('public_path_shape')
    return value

def _relative_member(value, root):
    value, root = _public_path(value), _public_path(root)
    prefix = root + '/'
    if not value.startswith(prefix): _reject('result_path_outside')
    relative = value[len(prefix):]
    if not relative or any(part in ('', '.', '..') for part in relative.split('/')):
        _reject('result_path_component')
    return relative

def _directory_identity(value):
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
            value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))

def _temp_anchor():
    if os.path.realpath(native_name(TEMP_ROOT)) != native_name(TEMP_ROOT):
        _reject('fixed_temp_root_resolved')
    value = os.lstat(native_name(TEMP_ROOT))
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_gid != 0:
        _reject('fixed_temp_root_profile')
    return _directory_identity(value)

def _owned_tree_current(base, original, anchor):
    if _temp_anchor() != anchor: _reject('fixed_temp_root_changed')
    base = _public_path(base)
    if os.path.dirname(base) != TEMP_ROOT:
        _reject('fresh_tree_parent')
    if not os.path.basename(base).startswith('mta-durable-network-device-'):
        _reject('fresh_tree_prefix')
    if os.path.realpath(native_name(base)) != native_name(base):
        _reject('fresh_tree_resolved_target')
    value = os.lstat(native_name(base))
    expected = _directory_identity(original)
    if (_directory_identity(value) != expected or expected[2] != stat.S_IFDIR or
            expected[3:6] != (0, 0, 0o700)):
        _reject('fresh_tree_identity')

def _write_payload(path, data):
    if type(data) is not bytes: _reject('source_payload_type')
    with io.open(native_name(path), 'wb') as output:
        if output.write(data) != len(data): _reject('source_payload_short_write')

def _read_payload(path):
    with io.open(native_name(path), 'rb') as source:
        value = source.read(262145)
        if source.read(1): _reject('retained_payload_over_cap')
    return value

def _file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size,
            getattr(value, 'st_mtime_ns', value.st_mtime),
            getattr(value, 'st_ctime_ns', value.st_ctime))

def _openssl_readonly():
    path = b'/usr/bin/openssl'
    original = os.lstat(path)
    if not stat.S_ISREG(original.st_mode) or not 0 < original.st_size <= 8388608:
        _reject('openssl_profile')
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    error, closed = None, False
    try:
        if _file_identity(os.fstat(fd)) != _file_identity(original):
            _reject('openssl_open_identity')
        digest, total = hashlib.sha256(), 0
        while total < original.st_size:
            part = os.read(fd, min(65536, original.st_size - total))
            if not part: _reject('openssl_early_eof')
            digest.update(part)
            total += len(part)
        if os.read(fd, 1): _reject('openssl_over_size')
        if digest.hexdigest() != OPENSSL_SHA: _reject('openssl_fixed_sha')
        if (_file_identity(os.fstat(fd)) != _file_identity(original) or
                _file_identity(os.lstat(path)) != _file_identity(original)):
            _reject('openssl_readback_identity')
    except BaseException as caught:
        error = caught
        raise
    finally:
        returned = os.close(fd)
        try:
            os.fstat(fd)
        except OSError as caught:
            closed = returned is None and type(caught.errno) is int and caught.errno == errno.EBADF
        if not closed: _reject('openssl_original_close_unknown')
    if error is not None or not closed: _reject('openssl_not_verified')
    if _file_identity(os.lstat(path)) != _file_identity(original):
        _reject('openssl_postclose_identity')
    return True

def _unpack(value, size, digest):
    raw = zlib.decompress(base64.b64decode(value))
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        _reject('embedded_source_identity')
    return raw

def _load_runtime(rows):
    modules = {}
    import_original = builtins.__import__
    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level: raise ImportError('relative_project_import_refused')
        if name in modules: return modules[name]
        if name.startswith(('mta_', 'p011_')):
            raise ImportError('unlisted_project_module')
        return import_original(name, globals, locals, fromlist, level)
    originals = []
    for name, size, digest, blob in rows:
        raw = _unpack(blob, size, digest)
        namespace = types.ModuleType(name)
        namespace.__file__ = 'embedded-' + name + '.py'
        namespace.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
        modules[name] = namespace
        exec(compile(raw, namespace.__file__, 'exec'), namespace.__dict__)
        originals.append((blob, size, digest, raw))
    if len(originals) != 7 or sum(row[1] for row in originals) != 197023:
        _reject('runtime_exact_total')
    return modules, originals
'''


def make_source(inputraws):
    """Pure fixed-input assembler; returned bytes are not executed here."""
    inputs = _fixed_inputs(inputraws)
    owner_source, phase_source = _select(inputs)
    adapted = _adapt_phase(phase_source)
    ast.parse(owner_source, feature_version=(3, 5))
    for path, unused_size, unused_digest in PINS[:7]:
        ast.parse(inputs[path].decode('utf-8'), feature_version=(3, 5))
    order = (
        ('p011_json', 3), ('mta_protocol', 2), ('mta_storage', 0),
        ('mta_files', 4), ('mta_transport', 1),
        ('mta_send_preparation', 5), ('mta_sender_pump', 6),
    )
    parts = [TARGET_HELPERS, '\nRUNTIME_ROWS = (\n']
    for name, index in order:
        path, size, digest = PINS[index]
        parts.append('    (%r, %d, %r,\n' % (name, size, digest))
        parts.append(_encoded(inputs[path]) + '),\n')
    owner_bytes = owner_source.encode('utf-8')
    phase_bytes = ('class _TargetTest(_Assertions):\n' + adapted).encode('utf-8')
    parts.append(')\nOWNER_BLOB = ' + _encoded(owner_bytes) + '\n')
    parts.append('PHASE_BLOB = ' + _encoded(phase_bytes) + '\n')
    parts.append('RESULT_FIXED = {\n')
    for key, value in RESULT_FIXED.items():
        parts.append('    %r: %r,\n' % (key, value))
    parts.append('}\n')
    parts.append('''
if os.name != 'posix' or not sys.platform.startswith('linux'):
    _reject('target_linux_required')
if os.geteuid() != 0 or os.uname()[4] != 'armv7l':
    _reject('target_uid_or_machine')
if tuple(sys.version_info[:3]) != (3, 5, 5):
    _reject('target_python_profile')
_openssl_readonly()
modules, original_runtime = _load_runtime(RUNTIME_ROWS)
owner_namespace = dict(errno=errno, threading=threading, time=time)
''')
    parts.append('owner_source = _unpack(OWNER_BLOB, %d, %r)\n' %
                 (len(owner_bytes), hashlib.sha256(owner_bytes).hexdigest()))
    parts.append("exec(compile(owner_source, 'TARGET_original_loopback_owner', 'exec'), owner_namespace)\n")
    parts.append('phase_source = _unpack(PHASE_BLOB, %d, %r)\n' %
                 (len(phase_bytes), hashlib.sha256(phase_bytes).hexdigest()))
    parts.append('''exec(compile(phase_source, 'TARGET_adapted_original_phase', 'exec'), globals())
test = _TargetTest()
elapsed = []
for phase in ('late_cancel', 'ack_loss'):
    elapsed.append(test._phase(modules, owner_namespace['_LoopbackOwner'], phase))
if len(elapsed) != 2 or any(type(value) is not float or not math.isfinite(value)
                           or not 0.0 <= value <= 35.0 for value in elapsed):
    _reject('phase_elapsed')
for blob, size, digest, raw in original_runtime:
    if _unpack(blob, size, digest) != raw: _reject('runtime_preserved')
result = dict(RESULT_FIXED)
result['phase_elapsed_seconds'] = tuple(elapsed)
print('P011_DURABLE_NETWORK=' + repr(result))
''')
    source = ''.join(parts).encode('ascii')
    if not 0 < len(source) <= TARGET_LIMIT or max(map(len, source.splitlines())) > MAX_LINE:
        _fail('target_source_budget')
    ast.parse(source.decode('ascii'), feature_version=(3, 5))
    if b'signal.alarm' in source or b'runpy' in source or b'unittest' in source:
        _fail('unexpected_target_controller')
    return source


def parse(raw):
    """Parse one selected derived result line; never normalize or replace raw logs."""
    if type(raw) is not bytes or not 0 < len(raw) <= OUTPUT_LIMIT:
        _fail('result_raw_budget')
    lines = raw.decode('ascii').splitlines()
    if len(lines) != 1 or not lines[0].startswith(RESULT_PREFIX.decode('ascii')):
        _fail('result_marker')
    row = ast.literal_eval(lines[0][len(RESULT_PREFIX):])
    if type(row) is not dict or set(row) != set(RESULT_FIELDS):
        _fail('result_exact_schema')
    for key, expected in RESULT_FIXED.items():
        if type(row[key]) is not type(expected) or row[key] != expected:
            _fail('result_fixed_value')
        if type(expected) is tuple:
            if any(type(actual) is not type(wanted)
                   for actual, wanted in zip(row[key], expected)):
                _fail('result_tuple_value_type')
    elapsed = row['phase_elapsed_seconds']
    if type(elapsed) is not tuple or len(elapsed) != 2:
        _fail('result_phase_elapsed_shape')
    if any(type(value) is not float or not math.isfinite(value)
           or not 0.0 <= value <= 35.0 for value in elapsed):
        _fail('result_phase_elapsed_range')
    return row


if __name__ == '__main__':
    raise SystemExit('PC maker requires ten fixed input byte strings; it does not execute a target')
