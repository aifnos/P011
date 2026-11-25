"""New libc flags adapter only: two complete Parent definitions, one method.

ROOT dispatches this once on HOST Linux. Platform ARM/Python/root predicates
are explicitly projected inside each private module; ctypes/CDLL/fcntl and
pipe FD operations are actual. Errno/invalid-return negatives use a private
instance library fault model. No Parent ctor/collect/Popen, Packet, Entry,
cap renewal, old test method, device, RF, admission or restoration executes.
"""
import builtins
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import sys
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SOURCES = (
    ('preflight', 'candidate/go-parent-libc-v1/runtime/mta_go_readonly_parent.py', 52873,
     '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
    ('terminal', 'candidate/go-parent-libc-v1/runtime/mta_go_readonly_terminal_parent.py', 66973,
     '42ef91c27805d080f80706097834c6a73e4d5fe7b7683533a60fb33e59025a7a'),
)
METHOD = 'ParentLibcPipeTest.test_ctypes_flags_and_real_pipe_lifecycle'
MARKER = ('HOST_PARENT_LIBC_PIPE new_methods=1 old_methods=0 domains=5 fixtures=10 '
          'kernel_pipes=true platform_model=true errno_fault_model=true device=false phone=false\n')
HOST_PYTHON_PIN = (6915048, 'ecf651f545bcef039d29503acf695a38903b7e8e9867a1ce0994ff6924e0274b')


class _Projection(object):
    def __init__(self, original, values):
        self.original = original
        self.values = values

    def __getattr__(self, name):
        return self.values[name] if name in self.values else getattr(self.original, name)


def _definition(spec, imported):
    label, relative, count, digest = spec
    raw = (BASE / relative).read_bytes()
    if len(raw) != count or hashlib.sha256(raw).hexdigest() != digest:
        raise AssertionError('new Parent SOURCE identity mismatch')
    original_import = builtins.__import__

    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'fcntl':
            imported.append(name)
            raise AssertionError('Python fcntl module import forbidden')
        if name.startswith(('mta_', 'p011_')) or level:
            raise AssertionError('unexpected project definition import')
        return original_import(name, globals, locals, fromlist, level)

    module = types.ModuleType('_host_parent_libc_' + label)
    module.__file__ = str(BASE / relative)
    local_builtins = dict(vars(builtins))
    local_builtins['__import__'] = restricted_import
    module.__dict__['__builtins__'] = local_builtins
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    # Only these original platform DATA predicates are modeled. No IO method
    # or new flags/validate function is patched, extracted or reimplemented.
    uname = tuple(os.uname())
    module.os = _Projection(os, {'geteuid': lambda: 0,
        'uname': lambda: uname[:4] + ('armv7l',),
        'O_NOFOLLOW': 0x8000, 'O_CLOEXEC': 0x80000})
    module.sys = _Projection(sys, {'platform': 'linux', 'byteorder': 'little',
        'version_info': (3, 5, 5)})
    return module


class _Pipes(object):
    """Fixture owns only os.pipe's original returned FDs, no GC close proof."""
    def __init__(self, test, closed_facts):
        self.test = test
        self.closed_facts = closed_facts
        self.rows = []

    def __enter__(self):
        pair = os.pipe()
        self.rows = [dict(fd=fd, close_called=False, closed=False, error=None) for fd in pair]
        return self

    @property
    def readfd(self): return self.rows[0]['fd']

    @property
    def writefd(self): return self.rows[1]['fd']

    def close_one(self, index, operation=os.close):
        row = self.rows[index]
        if row['close_called']:
            return
        row['close_called'] = True
        try:
            self.test.assertIsNone(operation(row['fd']))
            try:
                os.fstat(row['fd'])
            except OSError as error:
                self.test.assertIs(type(error.errno), int)
                self.test.assertEqual(errno.EBADF, error.errno)
                row['closed'] = True
                self.closed_facts.append((row, error))
            else:
                raise AssertionError('original pipe close did not produce typed EBADF')
        except BaseException as error:
            row['error'] = error
            raise

    def __exit__(self, kind, primary, traceback):
        errors = []
        for index in (1, 0):
            try:
                self.close_one(index)
            except BaseException as error:
                errors.append(error)
        if errors:
            if primary is not None:
                primary.host_pipe_cleanup_errors = tuple(errors)
            else:
                raise errors[0]
        return False


class _ErrnoFunction(object):
    """Explicit syscall-failure model; it never touches a kernel FD."""
    def __init__(self, result, code):
        self.result = result
        self.code = code
        self.calls = []

    def __call__(self, *arguments):
        self.calls.append(arguments)
        ctypes.set_errno(self.code)
        return self.result


class ParentLibcPipeTest(unittest.TestCase):
    def test_ctypes_flags_and_real_pipe_lifecycle(self):
        self.assertEqual('posix', os.name)
        self.assertEqual('linux', sys.platform)
        self.assertEqual((3, 13, 12), tuple(sys.version_info[:3]))
        self.assertEqual('6.6.87.2-microsoft-standard-WSL2', os.uname().release)
        self.assertEqual('x86_64', os.uname().machine)
        self.assertEqual(0, os.geteuid())
        python = Path(sys.executable).resolve().read_bytes()
        self.assertEqual(HOST_PYTHON_PIN, (len(python), hashlib.sha256(python).hexdigest()))
        self.assertEqual(2, len(SOURCES))
        imports, closed_facts, forbidden_calls = [], [], []
        modules = [_definition(spec, imports) for spec in SOURCES]
        codes = set()
        for module in modules:
            for cls_name in ('ReadonlyDataParent', 'ReadonlyTerminalParent'):
                cls = getattr(module, cls_name, None)
                if cls is not None:
                    for name in ('__init__', 'collect', 'close'):
                        codes.add(getattr(cls, name).__code__)
            codes.add(module._LinuxIo.spawn.__code__)
        old_profile = sys.getprofile()

        def tripwire(frame, event, arg):
            if event == 'call' and frame.f_code in codes:
                forbidden_calls.append(frame.f_code.co_name)
                raise AssertionError('unexpected Parent business/process operation')

        completed = 0
        try:
            sys.setprofile(tripwire)
            for module in modules:
                error_type = module.ReadonlyParentError
                with self.subTest(parent=module.__name__, domain='real_pipe'):
                    io = module._LinuxIo()
                    self.assertIsNone(io.validate())
                    self.assertIs(io._ctypes, ctypes)
                    self.assertIs(io._libc.fcntl, io._fcntl)
                    with _Pipes(self, closed_facts) as pair:
                        original_read = io.flags(pair.readfd)
                        original_write = io.flags(pair.writefd)
                        self.assertIs(type(original_read), int)
                        self.assertEqual(0, original_read & os.O_NONBLOCK)
                        self.assertEqual(0, original_write & os.O_NONBLOCK)
                        self.assertEqual(0, io.set_flags(pair.readfd, original_read | os.O_NONBLOCK))
                        self.assertEqual(original_read | os.O_NONBLOCK, io.flags(pair.readfd))
                        self.assertEqual(0, io.set_flags(pair.writefd, original_write | os.O_NONBLOCK))
                        self.assertEqual(original_write | os.O_NONBLOCK, io.flags(pair.writefd))
                        with self.assertRaises(OSError) as raised:
                            io.read(pair.readfd, 1)
                        self.assertIs(type(raised.exception.errno), int)
                        self.assertIn(raised.exception.errno, (errno.EAGAIN, errno.EWOULDBLOCK))
                        # Terminal's actual IO.write is the stdin-end operation;
                        # preflight has no write method and uses fixture os.write.
                        writer = io.write if hasattr(io, 'write') else os.write
                        self.assertEqual(1, writer(pair.writefd, b'K'))
                        self.assertEqual(b'K', io.read(pair.readfd, 1))
                        pair.close_one(1, io.close)
                        self.assertEqual(b'', io.read(pair.readfd, 1))
                        pair.close_one(0, io.close)
                    completed += 1
                with self.subTest(parent=module.__name__, domain='unvalidated'):
                    io = module._LinuxIo()
                    for function, arguments in ((io.flags, (0,)), (io.set_flags, (0, 0))):
                        with self.assertRaises(error_type) as raised:
                            function(*arguments)
                        self.assertEqual('parent_unvalidated', str(raised.exception))
                    completed += 1
                with self.subTest(parent=module.__name__, domain='arguments'):
                    io = module._LinuxIo(); io.validate()
                    with _Pipes(self, closed_facts) as pair:
                        original = io.flags(pair.readfd)
                        invalid = (True, False, -1, 0x80000000, 1.0, '1', None)
                        for value in invalid:
                            for function, arguments in ((io.flags, (value,)),
                                    (io.set_flags, (value, original)),
                                    (io.set_flags, (pair.readfd, value))):
                                with self.assertRaises(error_type) as raised:
                                    function(*arguments)
                                self.assertEqual('parent_fcntl_input', str(raised.exception))
                        self.assertEqual(original, io.flags(pair.readfd))
                    completed += 1
                with self.subTest(parent=module.__name__, domain='closed_fd'):
                    io = module._LinuxIo(); io.validate()
                    with _Pipes(self, closed_facts) as pair:
                        fd = pair.readfd
                        original = io.flags(fd)
                        pair.close_one(0, io.close)
                        for function, arguments in ((io.flags, (fd,)), (io.set_flags, (fd, original))):
                            with self.assertRaises(OSError) as raised:
                                function(*arguments)
                            self.assertEqual(errno.EBADF, raised.exception.errno)
                            self.assertEqual(-1, raised.exception.fcntl_result)
                            self.assertEqual(errno.EBADF, raised.exception.fcntl_errno)
                    completed += 1
                with self.subTest(parent=module.__name__, domain='errno_faults'):
                    for operation in ('get', 'set'):
                        for result, code, expected in ((-1, errno.EBADF, OSError),
                                (-1, 0, error_type), (-1, 4096, error_type),
                                (False, 0, error_type), ('bad', 0, error_type)):
                            io = module._LinuxIo(); io.validate()
                            modeled = _ErrnoFunction(result, code)
                            io._libc = types.SimpleNamespace(fcntl=modeled)
                            io._fcntl = modeled  # Explicit library/error ancestry fault, not method replacement.
                            with self.assertRaises(expected) as raised:
                                if operation == 'get': io.flags(7)
                                else: io.set_flags(7, os.O_NONBLOCK)
                            self.assertEqual(1, len(modeled.calls))
                            self.assertEqual((7, 3 if operation == 'get' else 4), modeled.calls[0][:2])
                            if operation == 'set':
                                self.assertIs(type(modeled.calls[0][2]), ctypes.c_int)
                                self.assertEqual(os.O_NONBLOCK, modeled.calls[0][2].value)
                            if expected is OSError:
                                self.assertEqual(errno.EBADF, raised.exception.errno)
                            elif type(result) is not int:
                                self.assertEqual('parent_fcntl_return', str(raised.exception))
                            else:
                                self.assertEqual('parent_fcntl_errno', str(raised.exception))
                    completed += 1
        finally:
            sys.setprofile(old_profile)
        self.assertEqual(10, completed)
        self.assertEqual(12, len(closed_facts))
        self.assertTrue(all(row['close_called'] and row['closed'] and row['error'] is None
                            for row, _ in closed_facts))
        self.assertEqual([], imports)
        self.assertEqual([], forbidden_calls)
        self.assertIs(sys.getprofile(), old_profile)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    if sys.argv[1:] != [METHOD]:
        raise SystemExit('Only the one new fixed method may be dispatched')
    unittest.main(argv=[sys.argv[0], METHOD], verbosity=1)
