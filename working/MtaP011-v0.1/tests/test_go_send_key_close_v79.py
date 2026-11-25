"""SOURCE-only HOST79: original key inventory and once-close bookkeeping.

One new method, fifteen independent fixtures, no previous TestCase or method.
The complete fixed Bridge79/crypto/protocol/p011_json definitions are private;
there is no sys.path fallback. Bridge's new four key methods and close/status
are unchanged. The normal path uses actual OpenSslCrypto.generate_keypair,
actual KeyPair construction/close and actual ctypes-owned DER buffers.

The FFI library is an explicit model: its positive integer is NOT an allocated
EC_KEY pointer and EC_KEY_free is a retained Python callback, not libcrypto.
Its modeled curve/SPKI facts prove no key mathematics or real native release.
Bridge construction/State/deployment/worker admission/clock are explicit inert
antecedents. No process, pipe, Pump, GO, GATT, RF, phone or restore executes.
Synthetic empty ancestor inventory can close locally, never issue permission.

Generation and free failures stay strongly retained, including actual
KeyPair.close's early closed=True/native_key=None before a modeled free error.
No 79 production method is replaced; function/library replacements below are
explicit negative continuity probes. The author must not run/import/AST this
SOURCE, WSL, ADB, or any old test method.
"""
import builtins
import ctypes
import hashlib
import json
from pathlib import Path
import sys
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ('host/go_send_key_close_v79_definition_manifest.json',
            'f770f7d5fd698ba939b336877fc3ccd31a2fc043b8f4740559b38a3e86bac593', 868)
SOURCES = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 8061),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 17958),
    ('mta_crypto', 'runtime/mta_crypto.py',
     '6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516', 15274),
    ('mta_go_send_bridge', 'candidate/go-send-key-close-v79/runtime/mta_go_send_bridge.py',
     '49d4a28c2156b8b99d0ac5965ec4f3cd4bdf617dddfbfcca90073e08e6a50cb4', 63045),
)
MARKER = ('HOST79_GO_SEND_KEY_CLOSE new_methods=1 old_methods=0 '
          'key_free_model=true device=false phone=false\n')


def _fixed(reference):
    if type(reference) is not tuple or len(reference) != 3:
        raise AssertionError('HOST79 graph is not SOURCE-sealed')
    raw = (ROOT / reference[0]).read_bytes()
    if len(raw) != reference[2] or hashlib.sha256(raw).hexdigest() != reference[1]:
        raise AssertionError('HOST79 fixed source changed')
    return raw


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST79 unrelated authority, IO or cryptographic operation forbidden')


class _NoIo(object):
    def __init__(self): self.calls = []

    def __getattr__(self, name):
        def forbidden(*args, **kwargs):
            self.calls.append(name)
            return _forbidden(*args, **kwargs)
        return forbidden


class _Definitions(object):
    def __init__(self):
        manifest = json.loads(_fixed(MANIFEST).decode('utf-8'))
        rows = manifest['sources']
        actual = tuple((row['module'], row['path'], row['sha256'], row['bytes']) for row in rows)
        if type(rows) is not list or actual != SOURCES:
            raise AssertionError('HOST79 exact four-definition graph changed')
        self.modules = {name: types.ModuleType(name) for name, path, digest, size in SOURCES}
        original_import = builtins.__import__

        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if not level and name in self.modules: return self.modules[name]
            if level or name.startswith(('mta_', 'p011_')):
                raise AssertionError('HOST79 undeclared private dependency')
            return original_import(name, globals, locals, fromlist, level)

        for name, path, digest, size in SOURCES:
            module = self.modules[name]
            module.__file__ = str(ROOT / path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            exec(compile(_fixed((path, digest, size)), name, 'exec'), module.__dict__)
        self.bridge, self.crypto = self.modules['mta_go_send_bridge'], self.modules['mta_crypto']
        self.io = _NoIo()
        self.bridge.os = self.io  # Private source domain only, no global os mutation.
        self.bridge.subprocess = _NoIo()
        self.crypto.OpenSslCrypto._load_library = _forbidden
        self.crypto.OpenSslCrypto.derive_shared = _forbidden
        self.crypto.OpenSslCrypto.encrypt_credentials = _forbidden
        self.crypto.OpenSslCrypto.decrypt_credentials = _forbidden


class _Clock(object):
    def __init__(self): self.value, self.calls, self.script = 1.0, 0, []

    def __call__(self):
        self.calls += 1
        if self.script: self.value = self.script.pop(0)
        return self.value


class _Library(object):
    """Explicit FFI model; every retained function is an instance original."""
    def __init__(self, crypto):
        self.pointer = 0x1234567  # Model integer only; never dereferenced as EC_KEY.
        self.events, self.freed = [], []
        self.generation_error = self.free_error = None
        self.on_generate = self.on_free = None
        self.der = crypto.P256_SPKI_PREFIX + b'\x11' * 64
        if len(self.der) != 91: raise AssertionError('HOST79 modeled SPKI shape changed')

        def allocate(nid):
            self.events.append(('allocate', nid))
            if nid != 415: raise AssertionError('HOST79 modeled curve changed')
            return self.pointer

        def asn1(key, flag):
            self.events.append(('asn1', key, flag))
            if key is not self.pointer or flag != 1: raise AssertionError('HOST79 modeled key changed')

        def generate(key):
            self.events.append(('generate', key))
            if key is not self.pointer: raise AssertionError('HOST79 modeled generation key changed')
            if self.on_generate is not None: self.on_generate()
            if self.generation_error is not None: raise self.generation_error
            return 1

        def group(key):
            self.events.append(('group', key))
            if key is not self.pointer: raise AssertionError('HOST79 modeled group key changed')
            return self.pointer

        def curve(group_pointer):
            self.events.append(('curve', group_pointer))
            if group_pointer is not self.pointer: raise AssertionError('HOST79 modeled group changed')
            return 415

        def check(key):
            self.events.append(('check', key))
            if key is not self.pointer: raise AssertionError('HOST79 modeled check key changed')
            return 1

        def spki(key, output):
            self.events.append(('spki', key, output is None))
            if key is not self.pointer: raise AssertionError('HOST79 modeled SPKI key changed')
            if output is not None:
                pointer = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
                address = pointer.contents.value  # Original Python-owned output buffer.
                ctypes.memmove(address, self.der, len(self.der))
                pointer.contents.value = address + len(self.der)
            return len(self.der)

        def free(key):
            self.events.append(('free', key)); self.freed.append(key)
            if key is not self.pointer: raise AssertionError('HOST79 modeled original free key changed')
            if self.on_free is not None: self.on_free()
            if self.free_error is not None: raise self.free_error
            return None

        # Method lookups return these SAME objects; no bound-method identity shortcut.
        self.EC_KEY_new_by_curve_name, self.EC_KEY_set_asn1_flag = allocate, asn1
        self.EC_KEY_generate_key, self.EC_KEY_get0_group = generate, group
        self.EC_GROUP_get_curve_name, self.EC_KEY_check_key = curve, check
        self.i2d_EC_PUBKEY, self.EC_KEY_free = spki, free


class _Fixture(object):
    def __init__(self, test):
        self.test, self.d = test, _Definitions()
        self.clock, self.until = _Clock(), 11.0
        self.library = _Library(self.d.crypto)
        self.crypto = object.__new__(self.d.crypto.OpenSslCrypto)
        self.crypto._lib = self.library
        self.bridge = object.__new__(self.d.bridge.GoSendBridge)
        b = self.bridge
        b.worker, b.clock, b.until = threading.current_thread(), self.clock, self.until
        # Constructor bypass is an explicit antecedent, not a State/parent grant.
        b.operation = types.SimpleNamespace(cancelled=threading.Event())
        b.prepared = types.SimpleNamespace(archive_size=0)
        b.rows, b.process, b.input, b.output, b.error_pipe = [], None, None, None, None
        b.process_called = b.process_unknown = b.process_reaped = False
        b._process_original = b._process_pid = None
        b.close_called = b.closed = b.cancel_sent = b.called = False
        b.failure = b.cleanup_until = b.returncode = b.result = None
        b.listening = b.intent = b.scan = b.key = None
        b.crypto = self.crypto
        b._key_generation = {'called': False, 'returned': False, 'value': None, 'originals': None,
            'native_key': None, 'error': None, 'unknown': False}
        b._key_release = {'called': False, 'returned': False, 'value': None,
            'error': None, 'unknown': False, 'verified': False}
        b._key_generation_original, b._key_release_original = b._key_generation, b._key_release
        b._consumed_gatt_original = None
        b._latest_progress, b._condition = None, threading.Condition()
        self.check_calls = 0

        def modeled_original_check():
            self.check_calls += 1
            if threading.current_thread() is not b.worker or b.until is not self.until:
                raise self.d.bridge.SendBridgeError('HOST79 original owner changed')
            now = self.clock()
            if now >= self.until: raise self.d.bridge.SendBridgeError('HOST79 active deadline')
            return now
        b._check = modeled_original_check  # Old source/State admission explicitly not exercised.

    def generate(self):
        return self.bridge._generate_key_original(self.d.crypto.OpenSslCrypto, self.d.crypto.KeyPair)

    def current(self):
        value, closer = self.bridge._key_current_original(False)
        self.test.assertIs(value, self.bridge.key)
        self.test.assertIs(closer, self.d.crypto.KeyPair.close)
        self.test.assertIs(self.bridge._key_generation_original['value'], value)
        self.test.assertIs(value._native_key, self.library.pointer)
        return value

    def pending(self):
        self.test.assertIs(self.bridge._key_closed_original(), False)
        value = self.bridge.status()
        self.test.assertIs(value['resource_pending'], True)
        self.test.assertIs(value['key_resource_closed'], False)
        self.test.assertIs(value['production_admitted'], False)
        self.test.assertIs(value['native_restore_verified'], False)
        self.test.assertIs(self.bridge.closed, False)
        self.test.assertEqual([], self.d.io.calls)

    def no_retry(self, expected_frees):
        release, failure, until = self.bridge._key_release_original, self.bridge.failure, self.bridge.cleanup_until
        events, clocks = len(self.library.events), self.clock.calls
        self.test.assertIs(self.bridge.close(61.0), False)
        self.test.assertIs(self.bridge._close_key_original(), False)
        self.test.assertIs(self.bridge.failure, failure)
        self.test.assertIs(self.bridge.cleanup_until, until)
        self.test.assertIs(self.bridge._key_release_original, release)
        self.test.assertEqual(events, len(self.library.events))
        self.test.assertEqual(clocks, self.clock.calls)
        self.test.assertEqual(expected_frees, len(self.library.freed))
        self.pending()


class GoSendKeyClose79Test(unittest.TestCase):
    def test_original_key_inventory_and_close(self):
        completed = []

        with self.subTest('zero_generation'):
            x = _Fixture(self); b = x.bridge
            self.assertIs(b.close(3.0), True)
            self.assertIs(b._key_closed_original(), True)
            self.assertIs(b._key_release_original['verified'], True)
            self.assertIs(b._key_generation_original['called'], False)
            self.assertIs(b._key_release_original['called'], False)
            self.assertIs(b._key_release_original['returned'], False)
            self.assertIsNone(b._key_release_original['value'])
            self.assertEqual([], x.library.events)
            self.assertIs(b.status()['key_resource_closed'], True)
            self.assertIs(b.status()['resource_pending'], False)  # Synthetic no-parent/no-FD ancestors only.
            clocks = x.clock.calls; self.assertIs(b.close(4.0), True)
            self.assertEqual(clocks, x.clock.calls)
            self.assertIs(b.status()['native_restore_verified'], False)
            self.assertEqual([], x.d.io.calls)
            completed.append('zero_generation')

        with self.subTest('normal_once'):
            x = _Fixture(self); b = x.bridge
            key = x.generate(); self.assertIs(x.current(), key)
            self.assertIs(type(key), x.d.crypto.KeyPair)
            self.assertEqual(2, x.check_calls)
            self.assertIs(b._key_generation_original['originals'][7], x.library.EC_KEY_free)
            self.assertIs(b.close(3.0), True)
            self.assertEqual([x.library.pointer], x.library.freed)
            self.assertIs(key.closed, True); self.assertIsNone(key._native_key)
            self.assertIs(b._key_release_original['returned'], True)
            self.assertIs(b._key_release_original['verified'], True)
            self.assertIsNone(b._key_release_original['error'])
            self.assertIs(b._key_release_original['unknown'], False)
            self.assertIsNone(b.failure)
            self.assertIs(b.status()['key_close_called'], True)
            self.assertIs(b.status()['key_resource_closed'], True)
            events, clocks = len(x.library.events), x.clock.calls
            self.assertIs(b.close(61.0), True)
            self.assertIs(b._close_key_original(), True)
            self.assertEqual(events, len(x.library.events)); self.assertEqual(clocks, x.clock.calls)
            self.assertIs(b.status()['native_restore_verified'], False)
            self.assertIs(b.status()['production_admitted'], False)
            self.assertEqual([], x.d.io.calls)
            completed.append('normal_once')

        with self.subTest('free_exception'):
            x = _Fixture(self); b = x.bridge; key = x.generate()
            primary = RuntimeError('HOST79 retained business failure')
            error = RuntimeError('HOST79 original modeled free failure')
            b.failure = primary; x.library.free_error = error
            self.assertIs(b.close(3.0), False)
            self.assertIs(key.closed, True); self.assertIsNone(key._native_key)  # Real KeyPair.close ordering.
            self.assertIs(b._key_release_original['error'], error)
            self.assertIs(b._key_release_original['called'], True)
            self.assertIs(b._key_release_original['returned'], False)
            self.assertIs(b._key_release_original['unknown'], True)
            self.assertIs(b._key_release_original['verified'], False)
            self.assertIs(b.failure, primary)
            x.no_retry(1)
            completed.append('free_exception')

        with self.subTest('generation_exception'):
            x = _Fixture(self); b = x.bridge
            error = RuntimeError('HOST79 original modeled generation failure')
            x.library.generation_error = error
            with self.assertRaises(RuntimeError) as caught: x.generate()
            self.assertIs(caught.exception, error)
            row = b._key_generation_original
            self.assertIs(row['called'], True); self.assertIs(row['returned'], False)
            self.assertIs(row['unknown'], True); self.assertIs(row['error'], error)
            self.assertIsNone(row['value']); self.assertIsNone(b.key)
            self.assertEqual([x.library.pointer], x.library.freed)  # Actual generate finally, modeled free only.
            b.failure = error  # Explicit caller-catch antecedent; no run_selected business replay.
            self.assertIs(b.close(3.0), False)
            self.assertIs(b.failure, error)
            self.assertEqual('key_inventory_original_changed', str(b._key_release_original['error']))
            x.no_retry(1)
            completed.append('generation_exception')

        with self.subTest('returned_key_replaced'):
            x = _Fixture(self); b = x.bridge; original = x.generate()
            replacement = x.d.crypto.KeyPair(original.public_key, x.library.pointer, x.library)
            b.key = replacement
            self.assertIs(b.close(3.0), False)
            self.assertIs(b._key_generation_original['value'], original)
            self.assertIs(original.closed, False); self.assertIs(replacement.closed, False)
            self.assertEqual('key_owner_original_changed', str(b._key_release_original['error']))
            x.no_retry(0)
            completed.append('returned_key_replaced')

        for changed in ('generator', 'closer', 'library', 'freer'):
            with self.subTest('source_' + changed):
                x = _Fixture(self); b = x.bridge; original = x.generate(); touched = []
                def foreign(*args, **kwargs):
                    touched.append(True); return _forbidden(*args, **kwargs)
                if changed == 'generator': x.d.crypto.OpenSslCrypto.generate_keypair = foreign
                elif changed == 'closer': x.d.crypto.KeyPair.close = foreign
                elif changed == 'library': x.crypto._lib = object()
                else: x.library.EC_KEY_free = foreign
                self.assertIs(b.close(3.0), False)
                self.assertEqual('key_owner_original_changed', str(b._key_release_original['error']))
                self.assertIs(original.closed, False); self.assertEqual([], touched)
                x.no_retry(0)
                completed.append('source_' + changed)

        with self.subTest('late_valid_return'):
            x = _Fixture(self); b = x.bridge
            x.library.on_generate = lambda: setattr(x.clock, 'value', x.until)
            with self.assertRaises(x.d.bridge.SendBridgeError) as caught: x.generate()
            self.assertEqual('HOST79 active deadline', str(caught.exception))
            row = b._key_generation_original
            self.assertIs(row['returned'], True); self.assertIs(row['unknown'], False)
            self.assertIsNone(row['error']); self.assertIs(row['value'], b.key)
            self.assertIs(row['native_key'], x.library.pointer)
            b.failure = caught.exception  # Model the caller retaining the original late business error.
            original_until = b.until
            self.assertIs(b.close(12.0), True)
            self.assertIs(b.until, original_until)
            self.assertEqual([x.library.pointer], x.library.freed)
            self.assertIs(b.failure, caught.exception); self.assertIs(b.status()['failed'], True)
            self.assertIs(b.status()['key_resource_closed'], True)
            self.assertIs(b.status()['native_restore_verified'], False)
            self.assertEqual([], x.d.io.calls)
            completed.append('late_valid_return')

        with self.subTest('cap_before_free'):
            x = _Fixture(self); b = x.bridge; key = x.generate()
            x.clock.script = [1.0, 2.0]  # First close cap accepted, then expires before free.
            self.assertIs(b.close(2.0), False)
            self.assertEqual('key_cleanup_expired', str(b._key_release_original['error']))
            self.assertIs(b._key_release_original['called'], False)
            self.assertIs(b._key_release_original['unknown'], True)
            self.assertIs(key.closed, False)
            x.no_retry(0)
            completed.append('cap_before_free')

        with self.subTest('cap_after_free'):
            x = _Fixture(self); b = x.bridge; key = x.generate()
            x.clock.script = [1.0, 1.0, 1.0, 2.0]  # Actual free returned; final cap check is late.
            self.assertIs(b.close(2.0), False)
            self.assertIs(key.closed, True); self.assertIsNone(key._native_key)
            self.assertIs(b._key_release_original['called'], True)
            self.assertIs(b._key_release_original['returned'], True)
            self.assertIs(b._key_release_original['unknown'], True)
            self.assertIs(b._key_release_original['verified'], False)
            self.assertEqual('key_cleanup_expired', str(b._key_release_original['error']))
            x.no_retry(1)
            completed.append('cap_after_free')

        with self.subTest('native_pointer_replaced'):
            x = _Fixture(self); b = x.bridge; key = x.generate()
            replacement = int(str(x.library.pointer))
            self.assertEqual(x.library.pointer, replacement); self.assertIsNot(x.library.pointer, replacement)
            key._native_key = replacement
            self.assertIs(b.close(3.0), False)
            self.assertEqual('key_native_original_changed', str(b._key_release_original['error']))
            x.no_retry(0)
            completed.append('native_pointer_replaced')

        with self.subTest('zero_phantom_inventory'):
            x = _Fixture(self); b = x.bridge; b.key = object()
            self.assertIs(b.close(3.0), False)
            self.assertIs(b._key_generation_original['called'], False)
            self.assertEqual('key_zero_inventory_unverified', str(b._key_release_original['error']))
            x.no_retry(0)
            completed.append('zero_phantom_inventory')

        with self.subTest('wrong_worker'):
            x = _Fixture(self); b = x.bridge; key = x.generate()
            b.worker = object(); clocks = x.clock.calls
            with self.assertRaises(x.d.bridge.SendBridgeError) as caught: b.close(3.0)
            self.assertEqual('parent_cleanup_worker', str(caught.exception))
            self.assertEqual(clocks, x.clock.calls); self.assertEqual([], x.library.freed)
            self.assertIs(b.close_called, False); self.assertIs(b._key_release_original['called'], False)
            self.assertIs(key.closed, False); x.pending()
            completed.append('wrong_worker')

        self.assertEqual(15, len(completed)); self.assertEqual(15, len(set(completed)))
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
