"""HOST mocks only: never initializes real Adb or creates an actual socket."""
import ast
import base64
import copy
import io
import json
import pathlib
import socket
import subprocess
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile
import zlib

PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'host'))
import device_udp_loopback as check


class Clock:
    def __init__(self):
        self.now = 10.0
    def monotonic(self):
        return self.now


class FakeSocket:
    def __init__(self, owner, n):
        self.owner, self.n = owner, n
        self.fd = owner.initial_fds[n]
        self.endpoint = None
        self.options = {}
        self.messages = []
        self.send_calls = 0
        self.close_calls = 0
        self.timeouts = []
    def fileno(self):
        if self.owner.fileno_error == self.n:
            raise OSError(5, 'private fileno error')
        return self.fd
    def settimeout(self, value):
        if not 0 < value <= 3:
            raise AssertionError('outside shared deadline')
        self.timeouts.append(value)
    def setsockopt(self, level, kind, value):
        self.options[(level, kind)] = value
        if self.owner.option_error == self.n:
            raise OSError(22, 'private option error')
    def getsockopt(self, level, kind, *args):
        if self.owner.bad_option == kind:
            return 0 if kind == 8 else b'wlan0\0'
        return self.options[(level, kind)]
    def bind(self, endpoint):
        if endpoint != ('127.0.0.1', 0):
            raise AssertionError('arbitrary bind')
        self.endpoint = ('127.0.0.1', self.owner.ports[self.n])
    def getsockname(self):
        return self.endpoint
    def sendmsg(self, data, ancillary, flags, endpoint):
        self.send_calls += 1
        self.owner.clock.now += self.owner.time_advance
        if self.owner.send_error:
            raise socket.timeout('private timeout')
        blob = b''.join(data)
        if flags != 0 or len(blob) > 64 or len(ancillary) != 1:
            raise AssertionError('outbound profile')
        level, kind, info = ancillary[0]
        if (level, kind) != (0, 8) or struct.unpack('I4s4s', info) != (
                1, b'\x7f\0\0\x01', b'\0' * 4):
            raise AssertionError('explicit source/interface missing')
        receiver = next(s for s in self.owner.sockets if s.endpoint == endpoint)
        receiver.messages.append((blob, [(0, 8, struct.pack('I4s4s', 1,
            b'\x7f\0\0\x01', b'\x7f\0\0\x01'))], 0, self.endpoint))
        return len(blob) - 1 if self.owner.short_send else len(blob)
    def recvmsg(self, maximum, ancsize):
        if maximum != 64 or ancsize != 32:
            raise AssertionError('unbounded receive')
        value = self.messages.pop(0)
        if self.owner.mutate is not None:
            value = self.owner.mutate(value)
        return value
    def close(self):
        self.close_calls += 1
        if self.owner.close_error == self.n:
            raise OSError(5, 'private close error')
        if self.owner.close_readback_fail != self.n:
            self.fd = -1


class FakeSockets:
    AF_INET = 2
    SOCK_DGRAM = 2
    IPPROTO_IP = 0
    SOL_SOCKET = 1
    SO_BINDTODEVICE = 25
    MSG_TRUNC = 32
    MSG_CTRUNC = 8
    timeout = socket.timeout
    @staticmethod
    def CMSG_SPACE(length):
        return length + 20
    def __init__(self, clock):
        self.clock, self.sockets = clock, []
        self.initial_fds, self.ports = [0, 4], [40000, 40001]
        self.option_error = self.bad_option = self.close_error = None
        self.close_readback_fail = self.fileno_error = None
        self.send_error = self.short_send = False
        self.time_advance = 0
        self.mutate = None
        owner = self
        class Factory:
            recvmsg = FakeSocket.recvmsg
            sendmsg = FakeSocket.sendmsg
            def __new__(cls, family, kind, protocol):
                if (family, kind, protocol) != (2, 2, 0) or len(owner.sockets) >= 2:
                    raise AssertionError('socket budget')
                value = FakeSocket(owner, len(owner.sockets))
                owner.sockets.append(value)
                return value
        self.socket = Factory


def body_result(configure=None, indices=(b'1\n', b'1\n')):
    clock = Clock()
    sockets = FakeSockets(clock)
    if configure is not None:
        configure(sockets)
    modules = {'socket': sockets, 'time': types.SimpleNamespace(monotonic=clock.monotonic),
               'sys': types.SimpleNamespace(flags=types.SimpleNamespace(optimize=0), version_info=(3, 5, 5))}
    values = iter(indices)
    def fixed_open(path, mode):
        if (path, mode) != ('/sys/class/net/lo/ifindex', 'rb'):
            raise AssertionError('unexpected filesystem read')
        return io.BytesIO(next(values))
    namespace = {'os': types.SimpleNamespace(geteuid=lambda: 0, uname=lambda: ('', '', '', '', 'armv7l')),
        're': check.re, 'require_stock': lambda s: None, 'stock_snapshot': lambda: {}, 'open': fixed_open}
    output = io.StringIO()
    with mock.patch.object(sys, 'stdout', output), mock.patch.dict(sys.modules, modules):
        exec(check.BODY, namespace)
    line = next(v[7:] for v in output.getvalue().splitlines() if v.startswith('RESULT='))
    return ast.literal_eval(line), sockets


def baseline():
    def row(name, pid):
        return {'pid': pid, 'name': name, 'parent': 1, 'starttime': '12', 'exe': '/usr/bin/' + name}
    stock = [row('Z03', 10), row('control_engine', 11), row('weston', 12)]
    for entry in stock[:2]:
        entry['parent_identity'] = row('launcher', 1)
    network = row('wpa_supplicant', 20)
    network['args_digest'] = 'a' * 64
    return {'stock': {'hashes': dict(check.STOCK_PINS), 'processes': [
        *stock]}, 'network_processes': [network], 'interfaces': [
            ('lo', (b'1\n', b'772\n', b'0x49\n', b'unknown\n')),
            ('wlan0', (b'22\n', b'1\n', b'0x1003\n', b'up\n'))],
        'station_state_digest': '1' * 64, 'main_ipv4_route_digest': '2' * 64,
        'ipv6_address_digest': '3' * 64, 'ipv6_route_digest': '4' * 64, 'boot_digest': '5' * 64}


class FakeAdb:
    results = []
    calls = []
    fail_label = None
    echo = False
    def __init__(self, directory):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True)
        self.index = 0
    def run(self, label, arguments, timeout=30, input_data=None):
        self.index += 1
        type(self).calls.append((label, arguments, timeout, input_data))
        if label == type(self).fail_label:
            raise RuntimeError('private host failure')
        value = type(self).results.pop(0)
        raw = ('RESULT=' + repr(value) + '\r\r\nMTA_REMOTE_OK\r\r\nMTA_REMOTE_EXIT=0\r\r\n').encode()
        if type(self).echo:
            raw = input_data.replace(b'\n', b'\r\r\n') + raw
        stem = '%02d-%s' % (self.index, label)
        (self.directory / (stem + '.stdout.raw')).write_bytes(raw)
        (self.directory / (stem + '.stderr.raw')).write_bytes(b'')
        (self.directory / (stem + '.host-exit')).write_text('0', encoding='ascii')
        return raw


class UdpLoopbackTests(unittest.TestCase):
    def setUp(self):
        FakeAdb.echo = False

    def test_success_zero_fd_is_valid_and_all_closed(self):
        value, sockets = body_result()
        self.assertTrue(value['pass'])
        self.assertEqual(check._udp_fields(value), value)
        self.assertEqual((value['sockets_created'], value['datagrams_sent'], value['datagrams_received']), (2, 4, 4))
        self.assertEqual([s.fd for s in sockets.sockets], [-1, -1])
        self.assertEqual([s.close_calls for s in sockets.sockets], [1, 1])

    def test_no_real_socket_in_host_mock(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('real socket forbidden')):
            self.assertTrue(body_result()[0]['pass'])

    def test_invalid_duplicate_or_negative_initial_fd(self):
        for fds in ([0, 0], [-1, 4], [True, 4]):
            value, sockets = body_result(lambda s: setattr(s, 'initial_fds', fds))
            self.assertFalse(value['pass'])
            self.assertTrue(all(s.close_calls == 1 for s in sockets.sockets))
            self.assertFalse(value['initial_fds_checked'])

    def test_missing_initial_fd_readback_never_passes(self):
        value, sockets = body_result(lambda s: setattr(s, 'fileno_error', 0))
        self.assertFalse(value['pass'])
        self.assertEqual(value['close_attempts'], 1)
        self.assertEqual(sockets.sockets[0].close_calls, 1)
        self.assertEqual(value['closed_readbacks'], 0)

    def test_options_readback_and_error_fail_closed(self):
        for kind in (8, 25):
            value, sockets = body_result(lambda s: setattr(s, 'bad_option', kind))
            self.assertFalse(value['pass'])
            self.assertEqual(value['error_stage'], 'options')
            self.assertTrue(all(s.close_calls == 1 for s in sockets.sockets))
        value, _ = body_result(lambda s: setattr(s, 'option_error', 0))
        self.assertEqual((value['error_class'], value['errno']), ('os_error', 22))

    def test_ports_are_ephemeral_distinct_and_not_dhcp(self):
        for ports in ([67, 40001], [68, 40001], [1023, 40001], [40000, 40000], [True, 40001]):
            value, _ = body_result(lambda s: setattr(s, 'ports', ports))
            self.assertFalse(value['pass'])
            self.assertEqual(value['error_stage'], 'bind')

    def test_index_is_canonical_positive_and_not_guessed(self):
        for raw in (b'0\n', b'01\n', b'-1\n', b'1private', b'2147483648\n', b'1\nextra'):
            value, sockets = body_result(indices=(raw,))
            self.assertFalse(value['pass'])
            self.assertEqual(len(sockets.sockets), 0)
        value, _ = body_result(indices=(b'1\n', b'2\n'))
        self.assertFalse(value['pass'])
        self.assertEqual(value['error_stage'], 'readback')

    def test_short_send_or_timeout_closes_all(self):
        for field in ('short_send', 'send_error'):
            value, sockets = body_result(lambda s: setattr(s, field, True))
            self.assertFalse(value['pass'])
            self.assertEqual(value['error_stage'], 'send')
            self.assertEqual([s.close_calls for s in sockets.sockets], [1, 1])

    def test_shared_three_second_deadline_stops_before_next_message(self):
        value, sockets = body_result(lambda s: setattr(s, 'time_advance', 4))
        self.assertFalse(value['pass'])
        self.assertEqual(value['datagrams_sent'], 1)
        self.assertEqual(value['datagrams_received'], 0)
        self.assertEqual([s.close_calls for s in sockets.sockets], [1, 1])

    def test_peer_payload_truncation_and_unexpected_flags(self):
        mutations = (
            lambda v: (b'wrong', v[1], v[2], v[3]),
            lambda v: (v[0], v[1], 32, v[3]),
            lambda v: (v[0], v[1], 8, v[3]),
            lambda v: (v[0], v[1], False, v[3]),
            lambda v: (v[0], v[1], 1, v[3]),
            lambda v: (v[0], v[1], 0, ('127.0.0.2', v[3][1])),
            lambda v: (v[0], v[1], 0, ('127.0.0.1', v[3][1] + 1)))
        for mutate in mutations:
            value, _ = body_result(lambda s: setattr(s, 'mutate', mutate))
            self.assertFalse(value['pass'])
            self.assertEqual(value['error_stage'], 'receive')

    def test_ancillary_exact_level_type_length_and_no_extra(self):
        for anc in ([], [(0, 8, b'bad')], [(1, 8, b'\0' * 12)],
                    [(0, 9, b'\0' * 12)], [(False, 8, b'\0' * 12)],
                    [(0, 8, b'\0' * 12)] * 2):
            value, _ = body_result(lambda s: setattr(s, 'mutate', lambda v: (v[0], anc, v[2], v[3])))
            self.assertFalse(value['pass'])

    def test_pktinfo_actual_interface_specdst_destination(self):
        local = b'\x7f\0\0\x01'
        for row in ((2, local, local), (1, b'\0' * 4, local), (1, local, b'\0' * 4)):
            anc = [(0, 8, struct.pack('I4s4s', *row))]
            value, _ = body_result(lambda s: setattr(s, 'mutate', lambda v: (v[0], anc, v[2], v[3])))
            self.assertFalse(value['pass'])

    def test_one_close_failure_does_not_skip_second_socket(self):
        value, sockets = body_result(lambda s: setattr(s, 'close_error', 0))
        self.assertFalse(value['pass'])
        self.assertEqual(value['error_stage'], 'close')
        self.assertEqual(value['close_attempts'], 2)
        self.assertEqual([s.close_calls for s in sockets.sockets], [1, 1])
        self.assertEqual(sockets.sockets[1].fd, -1)

    def test_failed_final_close_readback_is_not_success(self):
        value, _ = body_result(lambda s: setattr(s, 'close_readback_fail', 0))
        self.assertFalse(value['pass'])
        self.assertEqual((value['close_attempts'], value['closed_readbacks']), (2, 1))

    def test_body_schema_unknown_bool_count_errno_and_false_success(self):
        original = body_result()[0]
        cases = ({'private_endpoint': 'secret'}, {'sockets_created': True},
                 {'datagrams_sent': 5}, {'error_class': 'secret'}, {'errno': True},
                 {'errno': 4096}, {'all_sockets_closed': False}, {'closed_readbacks': 1})
        for changes in cases:
            value = dict(original)
            value.update(changes)
            with self.assertRaises(ValueError):
                check._udp_fields(value)

    def test_error_class_errno_are_sanitized(self):
        for error, expected in ((ValueError('private'), ('value_error', 0)),
                (OSError(5, 'private'), ('os_error', 5)), (OSError(5000, 'private'), ('os_error', 0)),
                (TimeoutError('private'), ('timeout', 0)), (RuntimeError('private'), ('runtime_error', 0)),
                (Exception('private'), ('unexpected', 0))):
            self.assertEqual(check._error(error), expected)

    def test_remote_exit_unique_and_complete_not_just_host_zero(self):
        raw = b'RESULT=True\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n'
        self.assertIs(check._parse(raw), True)
        for value in (b'RESULT=True\n', raw + b'MTA_REMOTE_EXIT=0\n',
                      raw.replace(b'EXIT=0', b'EXIT=1'), raw + b'RESULT=True\n',
                      raw + b'MTA_REMOTE_OK\n', raw + b'private extra text\n',
                      b'MTA_REMOTE_OK\nRESULT=True\nMTA_REMOTE_EXIT=0\n',
                      raw.replace(b'MTA_REMOTE_OK\n', b'MTA_REMOTE_OK\v\n'),
                      raw + b'\xff', b'x' * (check.MAX_OUTPUT + 1)):
            with self.assertRaises((ValueError, UnicodeError)):
                check._parse(value)

    def test_exact_complete_stdin_source_echo_only_normalizes_line_endings(self):
        _, sources = check.source_check()
        for source in sources:
            command, data, expected = check._transport(source)
            self.assertGreater(len(check._compressed_command(data)), 3500)
            self.assertIsNotNone(data)
            self.assertEqual(expected, data)
            result = b'RESULT=True\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n'
            for echo in (data, data.replace(b'\n', b'\r\n'), data.replace(b'\n', b'\r\r\n')):
                self.assertIs(check._parse(echo + result, expected), True)
            self.assertIs(check._parse(result, expected), True)  # ADB need not echo.

    def test_echo_truncated_changed_wrong_prefix_and_extra_markers_are_rejected(self):
        _, sources = check.source_check()
        _, data, expected = check._transport(sources[0])
        result = b'RESULT=True\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n'
        variants = (data[:-1], data[:-10], data.replace(b'import', b'Import', 1),
                    b'unknown\n' + data, data + b'unknown\n', data + b'MTA_REMOTE_OK\n',
                    data + b'MTA_REMOTE_EXIT=0\n', data + b'RESULT=True\n', data + data)
        for echo in variants:
            with self.assertRaises(ValueError):
                check._parse(echo + result, expected)
        with self.assertRaises(ValueError):
            check._parse(data + result)

    def test_short_transport_is_compressed_without_stdin_or_echo_permission(self):
        source = "print('RESULT=True')"
        command, data, expected = check._transport(source)
        self.assertLessEqual(len(command), 3500)
        self.assertIsNone(data)
        self.assertIsNone(expected)
        encoded = check.re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", command).group(1)
        self.assertEqual(zlib.decompress(base64.b64decode(encoded)),
                         (source + "\nprint('MTA_REMOTE_OK')\n").encode())
        self.assertNotIn('stdin', command)

    def test_transport_boundary_matches_full_command_not_payload_length(self):
        _, sources = check.source_check()
        for source in sources:
            command, data, expected = check._transport(source)
            self.assertLessEqual(len(command), 3500)
            self.assertIn('stdin.buffer.read(' + str(len(data)), command)
            self.assertEqual(data, expected)
        with self.assertRaises(ValueError):
            check._transport('x' * check.MAX_SOURCE)
        for bad in (b'source', None):
            with self.assertRaises(ValueError):
                check._transport(bad)

    def test_echo_argument_does_not_accept_arbitrary_container_or_unbounded_data(self):
        raw = b'RESULT=True\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n'
        for bad in ('source', b'', b'x' * (check.MAX_SOURCE + 1), bytearray(b'source')):
            with self.assertRaises(ValueError):
                check._parse(raw, bad)

    def owned_status(self, child, budget=lambda: 2):
        tree = ast.parse(check.BASELINE_BODY)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'owned_status')
        fake = types.SimpleNamespace(Popen=lambda *args, **kwargs: child, PIPE=-1)
        namespace = {'subprocess': fake, 'budget': budget}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<host-owned-status>', 'exec'), namespace)
        return namespace['owned_status']()

    def child(self, error=None, cleanup_error=False):
        child = mock.Mock()
        child.communicate.side_effect = error
        child.communicate.return_value = (b'wpa_state=COMPLETED\n', b'')
        child.returncode = 0
        child.poll.side_effect = [None, None if cleanup_error else -9]
        if cleanup_error:
            child.wait.side_effect = subprocess.TimeoutExpired('fixed', 0.5)
        return child

    def test_owned_query_child_cleaned_when_budget_raises_before_communicate(self):
        child = self.child()
        with self.assertRaises(ValueError):
            self.owned_status(child, lambda: (_ for _ in ()).throw(ValueError('budget')))
        child.kill.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=0.5)
        child.stdout.close.assert_called_once_with()
        child.stderr.close.assert_called_once_with()
        child.communicate.assert_not_called()

    def test_owned_query_child_cleaned_on_communicate_oserror_or_timeout(self):
        for error in (OSError(5, 'private'), subprocess.TimeoutExpired('fixed', 2)):
            child = self.child(error)
            with self.assertRaises(type(error)):
                self.owned_status(child)
            child.kill.assert_called_once_with()
            child.wait.assert_called_once_with(timeout=0.5)
            self.assertEqual(child.communicate.call_count, 1)
            child.stdout.close.assert_called_once_with()
            child.stderr.close.assert_called_once_with()

    def test_owned_query_cleanup_failure_closes_both_pipes_and_fails(self):
        child = self.child(cleanup_error=True)
        with self.assertRaisesRegex(ValueError, '^baseline_child_cleanup$'):
            self.owned_status(child)
        child.stdout.close.assert_called_once_with()
        child.stderr.close.assert_called_once_with()

    def test_owned_query_already_exited_is_not_killed(self):
        child = self.child()
        child.poll.side_effect = None
        child.poll.return_value = 0
        self.assertEqual(self.owned_status(child), b'wpa_state=COMPLETED\n')
        child.kill.assert_not_called()
        child.wait.assert_not_called()
        child.stdout.close.assert_called_once_with()
        child.stderr.close.assert_called_once_with()

    def test_baseline_not_partial_or_wrong_stock(self):
        self.assertEqual(check._baseline(baseline()), baseline())
        for mutate in (lambda v: v.pop('boot_digest'), lambda v: v.update(boot_digest='bad'),
                lambda v: v['stock']['hashes'].update({'/usr/bin/Z03': '0' * 64}),
                lambda v: v['stock']['processes'][0].update(pid=True),
                lambda v: v['interfaces'].pop(), lambda v: v['network_processes'][0].pop('args_digest'),
                lambda v: v['stock']['processes'][0].pop('parent_identity')):
            value = baseline()
            mutate(value)
            with self.assertRaises(ValueError):
                check._baseline(value)

    def test_source_only_default_does_not_initialize_adb_or_socket(self):
        with mock.patch.dict(sys.modules, {'device_probe': types.SimpleNamespace(
                Adb=lambda *a: (_ for _ in ()).throw(AssertionError('Adb forbidden')))}), \
                mock.patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('sys.stdout', io.StringIO()):
            self.assertEqual(check.main([]), 0)
            self.assertEqual(check.main(['--source-check-only']), 0)

    def test_fixed_pins_python35_ast_no_assert_or_candidate_import(self):
        result, sources = check.source_check()
        self.assertTrue(result['source_check_pass'])
        self.assertEqual(result['safety_sha256'], check.SAFETY_PIN)
        for source in sources:
            tree = ast.parse(source, feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
            self.assertNotIn('sys.path', source)
            self.assertNotIn('import mta_', source)
        self.assertNotIn('67', check.BODY)
        self.assertNotIn('68', check.BODY)

    def test_dependency_change_or_unknown_expected_pin_before_adb(self):
        with mock.patch.dict(sys.modules, {'device_probe': types.SimpleNamespace(
                Adb=lambda *a: (_ for _ in ()).throw(AssertionError('Adb forbidden')))}):
            with self.assertRaises(ValueError):
                check.run_reviewed('0' * 64)
        with mock.patch.object(check, 'SAFETY_PIN', '0' * 64):
            with self.assertRaises(ValueError):
                check.source_check()

    def test_cli_rejects_arbitrary_interface_address_port_or_ttl(self):
        for option in ('--interface', '--address', '--port', '--ttl'):
            with mock.patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                check.main([option, 'private'])
        with mock.patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
            check.main(['--execute-reviewed'])

    def runner(self, mutate=None, fail_label=None, echo=False):
        udp = body_result()[0]
        first, last = baseline(), baseline()
        if mutate is not None:
            mutate(last)
        FakeAdb.results = [first, udp, last]
        FakeAdb.calls = []
        FakeAdb.fail_label = fail_label
        FakeAdb.echo = echo
        checks, _ = check.source_check()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        destination = pathlib.Path(folder.name) / 'case'
        with mock.patch.dict(sys.modules, {'device_probe': types.SimpleNamespace(Adb=FakeAdb)}):
            result, out, archive = check.run_reviewed(checks['checker_sha256'], destination)
        return result, out, archive

    def test_host_fake_single_execution_archive_only_public(self):
        result, out, archive = self.runner()
        self.assertTrue(result['pass'])
        self.assertEqual([call[0] for call in FakeAdb.calls], ['before-loopback', 'fixed-loopback-only', 'after-loopback'])
        self.assertTrue(all(0 < call[2] <= 5 for call in FakeAdb.calls))
        self.assertTrue(all(call[1][0] == 'shell' for call in FakeAdb.calls))
        self.assertEqual(len(list((out / 'private-raw').glob('*.remote-exit'))), 3)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(bundle.namelist()), {'result.json', 'README.txt'})
            self.assertIsNone(bundle.testzip())
            public = bundle.read('result.json').decode()
            self.assertNotIn('127.0.0.1', public)
            self.assertNotIn('40000', public)
            self.assertNotIn('private', public)
        self.assertFalse(result['ipv4_all_tables_verified'])
        self.assertEqual(result['dhcp_exchange'], 'NOT_TESTED')

    def test_host_fake_complete_echo_pipeline_keeps_original_raw(self):
        result, out, archive = self.runner(echo=True)
        self.assertTrue(result['pass'])
        for i, call in enumerate(FakeAdb.calls, 1):
            raw = (out / 'private-raw' / ('%02d-%s.stdout.raw' % (i, call[0]))).read_bytes()
            self.assertTrue(raw.startswith(call[3].replace(b'\n', b'\r\r\n')))
            self.assertIn(b"print('MTA_REMOTE_OK')", raw)
            self.assertIn(b'MTA_REMOTE_EXIT=0', raw)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(bundle.namelist()), {'result.json', 'README.txt'})

    def test_compressed_remote_call_does_not_send_stdin_and_records_exit(self):
        FakeAdb.results, FakeAdb.calls = [True], []
        with tempfile.TemporaryDirectory() as directory:
            adb = FakeAdb(pathlib.Path(directory) / 'raw')
            self.assertIs(check._remote(adb, 'fixed-loopback-only', "print('RESULT=True')", 1), True)
            self.assertIsNone(FakeAdb.calls[0][3])
            self.assertIn('import base64,zlib', FakeAdb.calls[0][1][1])
            self.assertEqual((adb.directory / '01-fixed-loopback-only.remote-exit').read_text(), '0')

    def test_baseline_difference_fail_without_claiming_damage(self):
        for key in ('boot_digest', 'main_ipv4_route_digest', 'station_state_digest',
                    'ipv6_route_digest', 'ipv6_address_digest'):
            result, _, _ = self.runner(lambda v: v.update({key: '9' * 64}))
            self.assertFalse(result['pass'])
            self.assertFalse(result['independent_baseline_unchanged'])
            self.assertTrue(result['independent_stock_unchanged'])

    def test_after_is_attempted_once_after_udp_host_failure(self):
        # The UDP result is not consumed when the fake transport fails.
        FakeAdb.results = [baseline(), baseline()]
        FakeAdb.calls = []
        FakeAdb.fail_label = 'fixed-loopback-only'
        checks, _ = check.source_check()
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(sys.modules,
                {'device_probe': types.SimpleNamespace(Adb=FakeAdb)}):
            result, _, _ = check.run_reviewed(checks['checker_sha256'], pathlib.Path(directory) / 'case')
        self.assertFalse(result['pass'])
        self.assertEqual([c[0] for c in FakeAdb.calls], ['before-loopback', 'fixed-loopback-only', 'after-loopback'])
        self.assertEqual(result['host_error_class'], 'runtime_error')
        self.assertNotIn('private host failure', repr(result))

    def test_host_deadline_before_udp_does_not_invoke_trial(self):
        FakeAdb.results, FakeAdb.calls, FakeAdb.fail_label = [baseline()], [], None
        checks, _ = check.source_check()
        ticks = iter((0, 14, 14, 21))
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(sys.modules,
                {'device_probe': types.SimpleNamespace(Adb=FakeAdb)}), \
                mock.patch.object(check.time, 'monotonic', side_effect=lambda: next(ticks)):
            result, _, _ = check.run_reviewed(checks['checker_sha256'], pathlib.Path(directory) / 'case')
        self.assertFalse(result['pass'])
        self.assertFalse(result['udp_trial_invoked'])
        self.assertEqual([c[0] for c in FakeAdb.calls], ['before-loopback'])


if __name__ == '__main__':
    unittest.main()
