"""HOST-only V3 diagnostic candidate tests; no real netlink/ADB/RF writes."""
import errno
import importlib.util
import json
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

NATIVE = Path(__file__).resolve().parents[1]
SOURCE = NATIVE / 'private-p2p-runtime-candidate-20261001-v3' / 'runtime' / 'mta_send_wifi.py'
sys.path.insert(0, str(NATIVE.parent / 'runtime'))
spec = importlib.util.spec_from_file_location('mta_send_wifi_v3_diagnostic_candidate', str(SOURCE))
v3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v3)
from test_send_wifi_lease import MockBackend


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); os.chmod(self.temp.name, 0o700)
        self.journal = os.path.join(self.temp.name, 'lease.json'); self.backend = MockBackend()
        self.lease = v3.GoLease(self.backend, self.journal, lambda: 100.0)
    def tearDown(self): self.temp.cleanup()
    def start(self, watchdog=None): self.lease.start(20, watchdog or (lambda path, end: None))
    def fail(self, number, command=None):
        if command: raise v3.PrivateNetlinkError(number, command)
        raise OSError(number, 'private-password-and-interface-path', '/private/secret')
    def report(self, error): return self.lease.failure_info or v3.failure_diagnostic(self.lease.last_phase, error)
    def test_new_interface_kernel_failure_has_exact_fixed_phase_errno_command(self):
        self.backend.create = lambda name, phy: self.fail(errno.EBUSY, 'new_interface')
        with self.assertRaises(v3.PrivateNetlinkError) as caught: self.start()
        self.assertEqual(self.report(caught.exception), {'failure_phase': 'interface_create',
            'failure_errno': errno.EBUSY, 'netlink_command': 'new_interface'})
        self.assertFalse(self.backend.pending); self.assertIsNone(self.lease.state['owned'])
        self.assertNotIn('spawn', self.backend.calls)
    def test_fork_failure_in_watchdog_is_not_misreported_as_create(self):
        with self.assertRaises(OSError) as caught:
            self.start(lambda path, end: self.fail(errno.EAGAIN))
        self.assertEqual(self.report(caught.exception)['failure_phase'], 'watchdog_start')
        self.assertEqual(self.report(caught.exception)['failure_errno'], errno.EAGAIN)
        self.assertNotIn('create', self.backend.calls); self.assertFalse(self.backend.pending)
    def test_snapshot_failure_before_journal_has_no_fake_owned_cleanup(self):
        self.backend.snapshot = lambda exclude_owned=None: self.fail(errno.EACCES)
        with self.assertRaises(OSError) as caught: self.start()
        report = self.report(caught.exception)
        self.assertEqual(report['failure_phase'], 'baseline_snapshot'); self.assertEqual(report['failure_errno'], errno.EACCES)
        self.assertIsNone(self.lease.state); self.assertFalse(os.path.exists(self.journal))
    def test_capability_query_failure_is_distinct(self):
        self.backend.capabilities = lambda: self.fail(errno.ENOENT)
        with self.assertRaises(OSError) as caught: self.start()
        self.assertEqual(self.report(caught.exception)['failure_phase'], 'capability_query')
        self.assertFalse(os.path.exists(self.journal))
    def test_preexisting_interface_query_failure_is_distinct(self):
        self.backend.interfaces = lambda: self.fail(errno.ENOBUFS, 'get_interface')
        with self.assertRaises(v3.PrivateNetlinkError) as caught: self.start()
        self.assertEqual(self.report(caught.exception)['failure_phase'], 'existing_interfaces')
        self.assertEqual(self.report(caught.exception)['netlink_command'], 'get_interface')
        self.assertFalse(os.path.exists(self.journal))
    def test_interface_journal_failure_is_distinct_from_kernel_create(self):
        saved = self.lease._save
        def save(locked=False):
            if self.lease.state['stage'] == 'interface_created': self.fail(errno.ENOSPC)
            return saved(locked)
        self.lease._save = save
        with self.assertRaises(OSError) as caught: self.start()
        self.assertEqual(self.report(caught.exception)['failure_phase'], 'interface_journal')
        self.assertEqual(self.report(caught.exception)['failure_errno'], errno.ENOSPC)
        self.assertFalse(self.backend.rows); self.assertFalse(self.backend.pending)
    def test_cleanup_error_does_not_overwrite_original_failure_diagnostic(self):
        self.backend.create = lambda name, phy: self.fail(errno.EBUSY, 'new_interface')
        self.backend.stop_process = lambda record: self.fail(errno.EIO)
        with self.assertRaises(OSError) as caught: self.start()
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertEqual(self.report(caught.exception)['failure_errno'], errno.EBUSY)
        self.assertEqual(self.report(caught.exception)['failure_phase'], 'interface_create')
        self.assertTrue(self.backend.pending)
    def test_go_ready_unchanged_and_failure_fields_do_not_enter_journal(self):
        ready = self.lease.start(20, lambda path, end: None)
        self.assertEqual(ready, {'event': 'private_go_ready', 'ttl': 20, 'credentials_not_logged': True})
        record = json.loads(Path(self.journal).read_text())
        self.assertEqual(record['version'], 2); self.assertNotIn('last_phase', record)
        self.assertNotIn('failure_phase', record); self.assertIsNone(self.lease.failure_info)
        self.assertTrue(self.lease.stop()['complete'])


class SafeDiagnosticTests(unittest.TestCase):
    def test_errno_bounds_unknown_and_no_free_exception_text(self):
        for value in (None, False, True, -1, 0, 4096, '16'):
            error = OSError(16, 'PSK-private'); error.errno = value
            error.netlink_command = 'private-command'
            report = v3.failure_diagnostic('private-phase', error)
            self.assertEqual(report, {'failure_phase': 'not_started', 'failure_errno': 0,
                                     'netlink_command': 'not_recorded'})
            self.assertNotIn('private', json.dumps(report))
        for value in (1, 16, 4095):
            error = OSError(value, 'raw-secret-path', '/private/filename')
            report = v3.failure_diagnostic('interface_create', error)
            self.assertEqual(report['failure_errno'], value)
            self.assertNotIn('raw-secret', json.dumps(report)); self.assertNotIn('filename', json.dumps(report))
    def test_non_os_errors_do_not_guess_errno_from_args(self):
        error = v3.LeaseError('private-secret', 16)
        self.assertEqual(v3.failure_diagnostic('group_add', error)['failure_errno'], 0)
    def test_non_string_enum_metadata_is_safe_unknown(self):
        error = OSError(16, 'private-secret'); error.netlink_command = ['private-command']
        report = v3.failure_diagnostic(['private-phase'], error)
        self.assertEqual(report['failure_phase'], 'not_started')
        self.assertEqual(report['netlink_command'], 'not_recorded')
    def test_main_constructor_error_is_fixed_event_not_raw_traceback(self):
        argv = ['candidate', '--trial', '--run-dir', '/private/path', '--binary', '/private/wpa',
                '--caps-probe', '/private/caps', '--ttl', '20']
        output = io.StringIO()
        with mock.patch.object(v3, 'LinuxBackend', side_effect=OSError(errno.EACCES, 'private-secret', '/private/filename')):
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stdout', output):
                self.assertEqual(v3.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['failure_phase'], 'backend_construct')
        self.assertEqual(report['failure_errno'], errno.EACCES)
        self.assertEqual(report['reason'], 'os_error'); self.assertTrue(report['cleanup']['no_radio_mutation'])
        self.assertNotIn('private-secret', output.getvalue()); self.assertNotIn('filename', output.getvalue())
    def test_main_create_error_keeps_original_fixed_diagnostic_after_cleanup(self):
        argv = ['candidate', '--trial', '--run-dir', tempfile.gettempdir(), '--binary', '/private/wpa',
                '--caps-probe', '/private/caps', '--ttl', '20']
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); argv[3] = directory; backend = MockBackend()
            def create(name, phy): raise v3.PrivateNetlinkError(errno.EOPNOTSUPP, 'new_interface')
            backend.create = create; backend.diagnostic_report = lambda: {
                'events': [], 'diagnostic_invalid': False, 'raw_diagnostics_not_logged': True}
            backend.close = lambda: None; output = io.StringIO()
            with mock.patch.object(v3, 'LinuxBackend', return_value=backend), mock.patch.object(v3, 'start_watchdog', return_value=123):
                with mock.patch.object(v3.signal, 'signal'), mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stdout', output):
                    self.assertEqual(v3.main(), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report['failure_phase'], 'interface_create')
            self.assertEqual(report['failure_errno'], errno.EOPNOTSUPP)
            self.assertEqual(report['netlink_command'], 'new_interface')
            self.assertTrue(report['cleanup']['complete']); self.assertFalse(report['complete'])


class RequestTests(unittest.TestCase):
    class Socket:
        def __init__(self, packet=None, error=None, send_error=False):
            self.packet = packet; self.error = error; self.send_error = send_error
        def sendto(self, packet, addr):
            if self.send_error: raise self.error
        def settimeout(self, value): pass
        def recvmsg(self, size):
            if self.error: raise self.error
            return self.packet, [], 0, (0, 0)
    def request(self, sock, cmd=7):
        nl = v3.ReadWriteNetlink.__new__(v3.ReadWriteNetlink); nl.sock = sock; nl.sequence = 0
        return nl._request(42, cmd, b'', 4)
    def test_kernel_error_preserves_errno_without_extack_payload(self):
        body = struct.pack('i', -errno.EOPNOTSUPP) + b'PSK-private-kernel-extack'
        packet = struct.pack('IHHII', 16 + len(body), 2, 0, 1, 0) + body
        packet += b'\0' * ((-len(packet)) & 3)
        with self.assertRaises(v3.PrivateNetlinkError) as caught: self.request(self.Socket(packet=packet))
        report = v3.failure_diagnostic('interface_create', caught.exception)
        self.assertEqual(report['failure_errno'], errno.EOPNOTSUPP)
        self.assertEqual(report['netlink_command'], 'new_interface')
        self.assertNotIn('PSK', json.dumps(report))
    def test_socket_send_and_receive_errors_keep_command_and_errno(self):
        for sending in (True, False):
            error = OSError(errno.ENOBUFS, 'private-socket-path')
            with self.assertRaises(v3.PrivateNetlinkError) as caught:
                self.request(self.Socket(error=error, send_error=sending), cmd=5)
            report = v3.failure_diagnostic('interface_create', caught.exception)
            self.assertEqual(report['failure_errno'], errno.ENOBUFS)
            self.assertEqual(report['netlink_command'], 'get_interface')
    def test_socket_timeout_unknown_errno_is_not_fabricated(self):
        import socket
        with self.assertRaises(v3.PrivateNetlinkError) as caught:
            self.request(self.Socket(error=socket.timeout('private-timeout-text')))
        self.assertEqual(v3.failure_diagnostic('interface_create', caught.exception)['failure_errno'], 0)


if __name__ == '__main__': unittest.main()
