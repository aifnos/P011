"""Four new constructor guards; actual Linux directory FDs, no connection.

ROOT runs this new method once in a private WSL child. The complete fixed
transport/storage definitions execute; the clock wrapper calls actual original
time.monotonic. This does not construct a ClientTransfer lease or authenticate
radio/network admission. No old TestCase/helper or passed test method imports.
"""
import errno
import hashlib
import importlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
import warnings

BASE = Path(__file__).resolve().parents[1]
SOURCES = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_storage', 'candidate/receive-directory-fd-v1/runtime/mta_storage.py', 55562,
     'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('mta_transport', 'candidate/receive-directory-clock-v2/runtime/mta_transport.py', 40223,
     '171efb7cdfabbe4ea826afc03df6b401d1ee2b55cf23810e1fc7fb7b11f89826'),
)
MARKER = ('HOST_RECEIVE_DIRECTORY_CLOCK new_methods=1 old_methods=0 cases=4 '
          'linux_kernel=true device=false phone=false\n')


def _fixed_modules():
    for module, relative, count, digest in SOURCES:
        raw = (BASE / relative).read_bytes()
        if len(raw) != count or hashlib.sha256(raw).hexdigest() != digest:
            raise AssertionError('fixed SOURCE pin mismatch')
        if module in sys.modules:
            raise AssertionError('unexpected occupied project definition')
    # Only three fixed snapshot directories; no caller/sys.path source fallback.
    directories = [BASE / 'candidate/receive-directory-clock-v2/runtime',
                   BASE / 'candidate/receive-directory-fd-v1/runtime', BASE / 'runtime']
    original_path = list(sys.path)
    try:
        sys.path[:0] = [str(path) for path in directories]
        modules = {module: importlib.import_module(module) for module, _, _, _ in SOURCES}
    finally:
        sys.path[:] = original_path
    for module, relative, _, _ in SOURCES:
        if Path(modules[module].__file__).resolve() != (BASE / relative).resolve():
            raise AssertionError('unexpected project definition origin')
    return modules['mta_storage'], modules['mta_transport']


class _ClockWrapper(object):
    def __init__(self):
        self.original = time.monotonic
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.original()


def _ctor(transport, receiver, until, timer, connector, handoff):
    # Only the known HOST 3.13 deprecation is suppressed at its actual ctor
    # invocation, not all warnings or the production Python 3.5 TLS policy.
    with warnings.catch_warnings():
        warnings.filterwarnings('ignore', message=r'ssl\.PROTOCOL_TLSv1_2 is deprecated',
                                category=DeprecationWarning)
        return transport.ReceiverTransport('192.168.49.1', 12345, receiver,
            socket_factory=connector, source_ip='192.168.49.2', handoff=handoff,
            absolute_until=until, clock=timer)


class ReceiveDirectoryClockTest(unittest.TestCase):
    def test_wrapper_clock_and_binding_guards(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        storage, transport = _fixed_modules()
        self.assertIs(transport.DirectoryBinding, storage.DirectoryBinding)
        completed = 0
        for domain in ('wrapper_accepted', 'deadline_beyond_binding',
                       'scoped_binding_missing', 'binding_disappeared'):
            with self.subTest(domain=domain):
                with tempfile.TemporaryDirectory(prefix='host-receive-directory-clock-') as temporary:
                    root = Path(temporary) / 'Received'
                    root.mkdir(mode=0o700)
                    until = time.monotonic() + 20.0
                    binding = storage.DirectoryBinding(str(root), until)
                    receiver = storage.SafeZipReceiver(str(root), reserve_bytes=0,
                        directory_binding=None if domain == 'scoped_binding_missing' else binding)
                    timer = _ClockWrapper()
                    connector = mock.Mock(side_effect=AssertionError('unexpected scoped socket'))
                    handoff = mock.Mock(side_effect=AssertionError('unexpected socket handoff'))
                    value = None
                    primary = None
                    cleanup_errors = []
                    try:
                        self.assertIs(binding.absolute_until, until)
                        self.assertIs(binding.clock, time.monotonic)
                        self.assertIsNot(timer, binding.clock)
                        with mock.patch.object(transport.socket, 'create_connection',
                            side_effect=AssertionError('unexpected path fallback')) as fallback:
                            if domain == 'deadline_beyond_binding':
                                with self.assertRaises(transport.TransportError):
                                    _ctor(transport, receiver, until + 1.0, timer, connector, handoff)
                            elif domain == 'scoped_binding_missing':
                                with self.assertRaises(transport.TransportError):
                                    _ctor(transport, receiver, until, timer, connector, handoff)
                            else:
                                value = _ctor(transport, receiver, until, timer, connector, handoff)
                                self.assertIs(value.directory_binding, binding)
                                self.assertIs(value._directory_binding_original, binding)
                                self.assertIs(value._budget.clock, timer)
                                self.assertEqual(until, value.deadline)
                                self.assertEqual(until, value._budget.until)
                                if domain == 'binding_disappeared':
                                    receiver.directory_binding = None
                                    value.directory_binding = None
                                    with self.assertRaises(transport.TransportError):
                                        value._check()
                                    self.assertIs(value._directory_binding_original, binding)
                                else:
                                    self.assertGreater(value._check(), 0)
                                    self.assertGreater(timer.calls, 0)
                                    self.assertIs(value.close(0), True)
                                    self.assertTrue(value.closed())
                                    self.assertEqual(0, value.lifecycle_status()['socket_records'])
                                    self.assertIs(binding.check(), binding)  # Borrow remains open.
                            self.assertEqual(0, fallback.call_count)
                        self.assertEqual(0, connector.call_count)
                        self.assertEqual(0, handoff.call_count)
                    except BaseException as error:
                        primary = error
                        raise
                    finally:
                        # Every cleanup is attempted independently; first failure
                        # survives. Restore only this fixture's borrowed field.
                        receiver.directory_binding = binding if domain != 'scoped_binding_missing' else None
                        if value is not None:
                            try:
                                self.assertIs(value.close(0), True)
                            except BaseException as error:
                                cleanup_errors.append(error)
                        try:
                            self.assertIs(receiver.close(), True)
                        except BaseException as error:
                            cleanup_errors.append(error)
                        try:
                            last_fd = binding.rows[-1]['fd_original']
                            self.assertIs(binding.close(), True)
                            self.assertTrue(binding.closed())
                            with self.assertRaises(OSError) as badfd:
                                os.fstat(last_fd)  # Immediately before another open can reuse it.
                            self.assertEqual(errno.EBADF, badfd.exception.errno)
                            self.assertTrue(all(row['closed'] and not row['unknown'] for row in binding.rows))
                        except BaseException as error:
                            cleanup_errors.append(error)
                        if cleanup_errors:
                            if primary is not None:
                                primary.host_cleanup_errors = tuple(cleanup_errors)
                            else:
                                raise cleanup_errors[0]
                completed += 1
        self.assertEqual(4, completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
