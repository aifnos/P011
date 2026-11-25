"""Four new authentication-clock cases, SOURCE authored for ROOT's first run.

Complete pinned F/JSON/protocol/control-codec definitions execute in one private
definition forest. Actual DeploymentLoader ctor/authenticate, LoadedDeployment,
_receive_directory and ControlBinding methods are not replaced. The storage
type, directory/FS metadata and already-closed source rows are ancestry MODELS,
not Linux FD evidence. The Binding clock calls actual time.monotonic, while
the retained publication clock refuses every call as an ended phase.
No Loader.load, Factory publication, Parent, State, Native, child or RF runs.
"""
import builtins
import hashlib
from pathlib import Path
import stat
import sys
import time
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SOURCES = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 'candidate/client-integrated-v37/runtime/mta_client_control_frame.py', 20942,
     'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_executor', 'candidate/receive-directory-auth-clock-v2/runtime/mta_client_executor.py', 114074,
     '01dfd6295f2ac06464e7d7b0de1d99aa1ec97bef25f95222efa346609f25ecfb'),
)
MARKER = ('HOST_RECEIVE_DIRECTORY_AUTH_CLOCK new_methods=1 old_methods=0 cases=4 '
          'filesystem_model=true binding_model=true device=false phone=false\n')


def _definitions():
    modules = {}
    original_import = builtins.__import__

    def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in modules:
            if level:
                raise AssertionError('unexpected relative definition import')
            return modules[name]
        if level or name.startswith(('mta_', 'p011_')):
            raise AssertionError('unlisted project definition import')
        return original_import(name, globals, locals, fromlist, level)

    for name, relative, size, digest in SOURCES:
        raw = (BASE / relative).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise AssertionError('fixed SOURCE changed')
        module = types.ModuleType(name)
        module.__file__ = str(BASE / relative)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules['mta_client_executor'], modules['mta_client_control_frame']


class _PublicationEnded(object):
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError('ended publication clock must not be consulted')


class _BindingCapExpired(ValueError):
    pass


class _DirectoryModel(object):
    """No physical FD: original held rows/cap are explicit input models."""
    def __init__(self, root, until, identities):
        self.root = root
        self.absolute_until = until
        self.clock = time.monotonic
        self.identities = identities
        self.check_calls = 0

    def check(self):
        self.check_calls += 1
        if self.clock() >= self.absolute_until:
            raise _BindingCapExpired('original Binding cap expired')
        return self

    def identity_rows(self):
        return self.identities


class _FsModel(object):
    """Fixed observed-node projection, not HOST or P011 filesystem evidence."""
    paths = ('/', '/mnt', '/mnt/data', '/mnt/data/p011-toolbox',
             '/mnt/data/p011-toolbox/user', '/mnt/data/p011-toolbox/user/Received')
    components = ('/', 'mnt', 'data', 'p011-toolbox', 'user', 'Received')

    def __init__(self):
        identities = ((1, 1, stat.S_IFDIR | 0o755, 0, 0),
                      (1, 2, stat.S_IFDIR | 0o755, 0, 0),
                      (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000),
                      (66328, 30, stat.S_IFDIR | 0o700, 0, 0),
                      (66328, 31, stat.S_IFDIR | 0o700, 0, 0),
                      (66328, 32, stat.S_IFDIR | 0o700, 0, 0))
        self.entries = {path: types.SimpleNamespace(st_dev=values[0], st_ino=values[1],
            st_mode=values[2], st_uid=values[3], st_gid=values[4], st_nlink=2, st_size=0)
            for path, values in zip(self.paths, identities)}
        self.identities = tuple((name,) + values for name, values in zip(self.components, identities))
        self.receive_metadata = tuple(zip(self.paths, identities))
        self.calls = []

    def stat(self, path):
        if path not in self.entries:
            raise AssertionError('unexpected source path')
        self.calls.append(path)
        return self.entries[path]

    def __getattr__(self, name):
        raise AssertionError('unexpected filesystem/process operation')


def _loaded_ancestry(f, codec, domain):
    io, publication = _FsModel(), _PublicationEnded()
    now = time.monotonic()
    task_until = now - 1.0 if domain == 'task_expired' else now + 60.0
    binding_until = now - 1.0 if domain == 'binding_expired' else now + 60.0
    directory = _DirectoryModel(f.RECEIVE_ROOT, binding_until, io.identities)
    storage = types.ModuleType('mta_storage')
    storage.DirectoryBinding = _DirectoryModel
    # Constructor's canonical storage lookup is an isolated namespace MODEL,
    # not a global sys.modules overwrite or a loaded private storage graph.
    f.sys = types.SimpleNamespace(modules={'mta_storage': storage})
    loader = f.DeploymentLoader('a' * 32, 'b' * 64, _io=io, _clock=publication,
        _parent_until_v33=task_until, _receive_directory_binding=directory)
    metadata = dict(version=1, run_token='a' * 32, candidate_sha='b' * 64,
        operation_id='c' * 32, native_epoch=1, operation_epoch=1,
        gatt_session=1, nonce='d' * 32, receive_consent=True)
    control = codec.ControlBinding(metadata)  # Actual pure DATA validator, no consent issuer.
    loader.modules = {'mta_client_control_frame': codec}
    loader._connect_metadata = metadata
    loader._connect_binding, loader._connect_wire = control, control._wire
    loader._directory_identity_original = directory.identity_rows()
    # Actual source owner definition; its prior file close inventory is MODEL.
    # Its phase clock/cap are already unavailable, and authenticate must not
    # renew that phase or call ReadOwner.check/load again.
    loader.owner = f._ReadOwner(io, publication, now - 1.0)
    loader.owner.rows.append({'closed': True, 'unknown': False})
    provider = types.SimpleNamespace(run_token=metadata['run_token'], candidate_sha=metadata['candidate_sha'])
    value = f.LoadedDeployment(loader, loader.modules, provider, loader.expected, loader.run,
        control, f.RECEIVE_ROOT, io.receive_metadata, directory)
    loader.value = value
    if domain == 'directory_changed':
        io.entries[f.RECEIVE_ROOT].st_ino += 1
    return loader, value, directory, publication, io


class ReceiveDirectoryAuthClockTest(unittest.TestCase):
    def test_authenticate_uses_original_directory_clock(self):
        f, codec = _definitions()
        authenticate, read_directory = f.DeploymentLoader.authenticate, f._receive_directory
        completed = 0
        for domain in ('publication_ended', 'task_expired', 'binding_expired', 'directory_changed'):
            with self.subTest(domain=domain):
                loader, value, binding, publication, io = _loaded_ancestry(f, codec, domain)
                task_cap, directory_cap = loader._parent_until_original_v33, binding.absolute_until
                self.assertIs(loader.clock, publication)
                self.assertIs(loader.owner.clock, publication)
                self.assertIs(binding.clock, time.monotonic)
                self.assertIsNot(loader.clock, binding.clock)
                self.assertIs(value.receive_directory_binding, binding)
                self.assertIs(value._receive_directory_original, binding)
                if domain == 'publication_ended':
                    self.assertGreater(task_cap, time.monotonic())
                    self.assertGreater(directory_cap, time.monotonic())
                    self.assertIsNone(loader.authenticate(value))
                    self.assertEqual(list(io.paths), io.calls)
                    self.assertGreater(binding.check_calls, 0)
                elif domain == 'task_expired':
                    self.assertLess(task_cap, time.monotonic())
                    self.assertGreater(directory_cap, time.monotonic())
                    with self.assertRaises(f.ExecutorError) as error:
                        loader.authenticate(value)
                    self.assertEqual('deadline', error.exception.code)
                    self.assertEqual([], io.calls)
                elif domain == 'binding_expired':
                    self.assertGreater(task_cap, time.monotonic())
                    self.assertLess(directory_cap, time.monotonic())
                    with self.assertRaises(_BindingCapExpired):
                        loader.authenticate(value)
                    self.assertEqual([], io.calls)
                else:
                    self.assertGreater(task_cap, time.monotonic())
                    self.assertGreater(directory_cap, time.monotonic())
                    with self.assertRaises(f.ExecutorError) as error:
                        loader.authenticate(value)
                    self.assertEqual('source_changed', error.exception.code)
                    self.assertEqual(list(io.paths), io.calls)
                self.assertEqual(0, publication.calls)
                self.assertIs(loader.clock, publication)
                self.assertIs(loader._parent_until_original_v33, task_cap)
                self.assertIs(binding.absolute_until, directory_cap)
                self.assertIs(f.DeploymentLoader.authenticate, authenticate)
                self.assertIs(f._receive_directory, read_directory)
                self.assertEqual([], f._ENTRY_OWNERS)
                completed += 1
        self.assertEqual(4, completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
