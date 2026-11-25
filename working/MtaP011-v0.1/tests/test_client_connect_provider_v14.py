"""v14 new Fake cases only; no OS/association/kernel/phone evidence."""
import ast
import builtins
import hashlib
import importlib.util
import socket
import struct
import sys
import types
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_connection as old
from test_client_files import PENDING

CANDIDATE = BASE / 'candidate/client-connect-v14/runtime'


def load(name, path, imports=None):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    if imports is not None:
        namespace = dict(vars(builtins)); original = builtins.__import__
        def private_import(name, *args, **kwargs):
            return imports[name] if name in imports else original(name, *args, **kwargs)
        namespace['__import__'] = private_import
        value.__dict__['__builtins__'] = namespace
    spec.loader.exec_module(value)
    return value


c = load('connection_v14_private', CANDIDATE / 'mta_client_connection.py')
alias = load('alias_v14_fixture_private', BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py')
p = load('provider_v14_private', CANDIDATE / 'mta_client_linux_provider.py',
    {'mta_client_connection': c, 'mta_client_tmp_alias': alias})


def fixture(function, changes):
    namespace = dict(function.__globals__); namespace.update(changes)
    return types.FunctionType(function.__code__, namespace, function.__name__,
        function.__defaults__, function.__closure__)


def manifest():
    return p.ProviderManifest({'version': 1, 'run_token': old.TOKEN, 'candidate_sha': 'a' * 64,
        'ifname': old.OWNED.name, 'baseline_manifest': p.core.STOCK_PINS + ((p.baseline.CLI, 'b' * 64),),
        'status_manifest': {'daemon_exe': '/usr/sbin/wpa_supplicant', 'daemon_sha256': 'c' * 64,
            'endpoint': '/var/run/wpa_supplicant/wlan0', 'real_uid': 0, 'real_gid': 0,
            'namespace_kind': 'namespaces_disabled_cgroup_mnt', 'config_sha256': 'd' * 64},
        'wpa_exe': p.tmp_alias.PHYSICAL_TMP + '/p011-mta-client-rfinit/client-' + old.TOKEN + '/native/mta-wpa-supplicant',
        'wpa_sha': p.core.WPA_SHA, 'python_exe': '/usr/bin/python3.5', 'python_sha': 'e' * 64,
        'executor_path': old.RUN + '/mta_client_executor.py', 'executor_sha': 'f' * 64},
        _manifest_sha256='1' * 64)


class ConnectProviderV14Tests(unittest.TestCase):
    setUp = fixture(old.ConnectionTests.setUp, {'p': p})
    make = fixture(old.ConnectionTests.make, {'p': p, 'c': c, 'manifest': manifest})

    def reject(self, lease, checkpoint, expected='cancelled'):
        with self.assertRaises(c.ConnectionError) as error:
            lease.connect_p2p(old.info(), _checkpoint=checkpoint)
        self.assertEqual(expected, error.exception.code)
        op = lease.provider._connection
        self.assertIsNotNone(op); self.assertTrue(op.failed)
        self.assertEqual(expected, op.reason)
        return op

    def retained(self, lease, provider, store, io):
        self.assertFalse(lease.cleanup_complete); self.assertIn(PENDING, io.nodes)
        self.assertEqual(0, sum(raw.close_calls for raw in io.sockets))
        self.assertFalse(provider.status()['send_available'])
        self.assertFalse(provider.status()['receive_available'])

    def test_false_callback_same_owner_connect_readback_disconnect_original_ttl(self):
        lease, provider, store, io = self.make(); calls = []
        def checkpoint(): calls.append(1); return False
        original_deadline = lease.record.deadline
        first = lease.connect_p2p(old.info(), _checkpoint=checkpoint)
        op = provider._connection
        self.assertIs(op._cancel_checkpoint, checkpoint)
        self.assertIs(type(first), c.ConnectionObservation)
        second = lease.read_connection(first)
        self.assertIs(second, op.result); self.assertIsNot(second, first)
        self.assertTrue(lease.disconnect_p2p()['disconnect_observed'])
        self.assertEqual(original_deadline, lease.record.deadline)
        self.assertEqual(original_deadline, op.deadline)
        self.assertGreater(len(calls), 20)
        self.assertEqual([b'ATTACH'], io.sockets[1].sent)
        self.assertEqual(1, io.sockets[0].sent.count(b'ADD_NETWORK'))
        self.assertFalse(first.public_summary()['ip_verified'])
        self.retained(lease, provider, store, io)

    def test_missing_or_true_callback_retains_once_operation_no_handoff_or_new_socket(self):
        for callback in (None, lambda: True):
            lease, provider, store, io = self.make()
            op = self.reject(lease, callback)
            self.assertEqual(6, len(store._coordination._inventory))
            self.assertEqual(1, len(io.sockets)); self.assertEqual([], io.sockets[0].sent)
            self.assertIs(op._cancel_checkpoint, callback)
            with self.assertRaises(c.ConnectionError) as again:
                lease.connect_p2p(old.info(), _checkpoint=lambda: False)
            self.assertEqual('already_attempted', again.exception.code)
            self.retained(lease, provider, store, io)

    def test_nonbool_or_callback_baseexception_fixed_cancelled_no_secret(self):
        def interrupted(): raise KeyboardInterrupt('private credential not public')
        for callback in (lambda: 0, lambda: 1, lambda: 'private', interrupted):
            lease, provider, store, io = self.make()
            op = self.reject(lease, callback)
            self.assertTrue(provider.cancelled.is_set())
            self.assertNotIn('private', repr(op.status()))
            self.retained(lease, provider, store, io)

    def test_cancel_after_actual_reacquire_keeps_exact_new_locks_for_restore(self):
        lease, provider, store, io = self.make(); original = store.acquire; flag = [False]
        def acquire(*args):
            value = original(*args); flag[0] = True; return value
        store.acquire = acquire
        op = self.reject(lease, lambda: flag[0])
        self.assertIs(lease.locks, op.reacquired)
        self.assertIs(lease.locks, store._current_locks); self.assertTrue(lease._restore_held)
        self.assertEqual(7, len(store._coordination._inventory))
        self.assertEqual(1, len(io.sockets)); self.assertEqual([], io.sockets[0].sent)

    def test_cancel_after_full_fresh_no_event_socket_or_commands(self):
        lease, provider, store, io = self.make(); original = lease._baseline; flag = [False]
        def snapshot(*args):
            value = original(*args); flag[0] = True; return value
        lease._baseline = snapshot
        self.reject(lease, lambda: flag[0])
        self.assertEqual(1, len(io.sockets)); self.assertEqual([], io.sockets[0].sent)
        self.assertTrue(lease._restore_held)

    def test_cancel_immediately_before_send_has_no_subsequent_wire(self):
        lease, provider, store, io = self.make(); flag = [False]
        original = provider._connection_timeout
        def timeout(*args): original(*args); flag[0] = True
        provider._connection_timeout = timeout
        self.reject(lease, lambda: flag[0])
        self.assertEqual([[], []], [raw.sent for raw in io.sockets])
        self.retained(lease, provider, store, io)

    def test_cancel_after_reply_retains_actual_packet_no_network_command(self):
        lease, provider, store, io = self.make(); flag = [False]
        def hook(raw, wire):
            if wire == b'ADD_NETWORK': flag[0] = True
        io.command_hook = hook
        op = self.reject(lease, lambda: flag[0])
        self.assertEqual([b'ADD_NETWORK'], io.sockets[0].sent)
        # Callback before receive prevents further IO; sent reply remains on the
        # exact retained original socket, not a fabricated consumed packet.
        self.assertEqual(b'0\n', io.sockets[0].queue[0][0])
        self.assertFalse(op.group_requested); self.retained(lease, provider, store, io)

    def test_cancel_after_recv_saves_original_reply_before_checkpoint(self):
        lease, provider, store, io = self.make(); flag = [False]
        raw = io.sockets[0]; original = raw.recvmsg; returned = []
        def recv(*args):
            value = original(*args); returned.append(value); flag[0] = True; return value
        raw.recvmsg = recv
        op = self.reject(lease, lambda: flag[0])
        self.assertIs(op._packets[-1], returned[-1])
        self.assertIs(provider._ctrl_incoming[-1], returned[-1])
        self.assertFalse(provider._ctrl_receive_unknown)
        self.assertEqual([b'ADD_NETWORK'], raw.sent)
        self.retained(lease, provider, store, io)

    def test_cancel_after_event_recv_saves_group_but_issues_no_status(self):
        lease, provider, store, io = self.make(); flag = [False]
        original = provider._connection_open; returned = []
        def channel(*args, **kwargs):
            row = original(*args, **kwargs)
            if kwargs.get('event') and not returned:
                actual = row.value.recvmsg
                def recv(*a):
                    value = actual(*a)
                    if value[0].startswith(b'<3>P2P-GROUP-STARTED'):
                        returned.append(value); flag[0] = True
                    return value
                row.value.recvmsg = recv
            return row
        provider._connection_open = channel
        op = self.reject(lease, lambda: flag[0])
        self.assertIs(op._packets[-1], returned[-1]); self.assertIsNone(op.result)
        self.assertNotIn(b'STATUS', io.sockets[0].sent)
        self.retained(lease, provider, store, io)

    def test_poll_eagain_checkpoint_can_revoke_before_add_network(self):
        lease, provider, store, io = self.make(); flag = [False]
        original = provider._connection_timeout
        def timeout(raw, deadline, poll):
            original(raw, deadline, poll)
            if poll:
                actual = raw.recvmsg
                def recv(*args):
                    try: return actual(*args)
                    finally: flag[0] = True
                raw.recvmsg = recv
        provider._connection_timeout = timeout
        op = self.reject(lease, lambda: flag[0])
        self.assertEqual([], io.sockets[0].sent); self.assertTrue(op.attached)
        self.assertFalse(provider._ctrl_receive_unknown)

    def cancellation_of_observed(self, method):
        lease, provider, store, io = self.make(); flag = [False]
        first = lease.connect_p2p(old.info(), _checkpoint=lambda: flag[0])
        before = tuple(io.sockets[0].sent); flag[0] = True
        with self.assertRaises(c.ConnectionError) as error:
            lease.read_connection(first) if method == 'readback' else lease.disconnect_p2p()
        self.assertEqual('cancelled', error.exception.code)
        self.assertIs(first, provider._connection.result)
        self.assertEqual(before, tuple(io.sockets[0].sent))
        self.assertTrue(provider._connection.failed)
        self.retained(lease, provider, store, io)

    def test_readback_and_disconnect_cancel_keep_observation_and_no_new_commands(self):
        self.cancellation_of_observed('readback')

    def test_disconnect_cancel_keeps_observation_and_no_new_commands(self):
        self.cancellation_of_observed('disconnect')

    def test_blocking_receive_timeout_checkpoint_revokes_before_retry(self):
        lease, provider, store, io = self.make(); flag = [False]
        original = provider._connection_open
        def channel(*args, **kwargs):
            row = original(*args, **kwargs)
            if kwargs.get('event'):
                actual = row.value.recvmsg
                def recv(*a):
                    if row.value.timeout != 0 and provider._connection.group_requested:
                        flag[0] = True; raise socket.timeout('private timeout')
                    return actual(*a)
                row.value.recvmsg = recv
            return row
        provider._connection_open = channel
        op = self.reject(lease, lambda: flag[0])
        self.assertTrue(op.group_requested); self.assertIsNone(op.result)
        self.assertNotIn(b'STATUS', io.sockets[0].sent)
        self.assertFalse(provider._ctrl_receive_unknown)
        self.retained(lease, provider, store, io)

    def test_scm_rights_on_cancel_retained_in_same_ledger_not_blind_closed(self):
        lease, provider, store, io = self.make(); flag = [False]
        io.add(old.RUN + '/received', old.stat.S_IFREG | 0o600)
        fd = io._open(old.RUN + '/received', 0, 0)
        raw = io.sockets[0]; original = raw.recvmsg
        def recv(*args):
            packet, ancillary, flags, address = original(*args)
            flag[0] = True
            return packet, ancillary + [(1, 1, struct.pack('i', fd))], flags, address
        raw.recvmsg = recv
        with self.assertRaises(p.LinuxProviderError):
            lease.connect_p2p(old.info(), _checkpoint=lambda: flag[0])
        self.assertEqual(1, len(provider._ctrl_rights))
        row = provider._ctrl_rights[0]
        self.assertEqual(fd, row.fd); self.assertTrue(row.returned)
        self.assertFalse(row.attempted); self.assertFalse(row.closed)
        self.assertTrue(provider._connection.failed)
        self.retained(lease, provider, store, io)

    def test_final_drain_revocation_is_preserved_in_v14(self):
        lease, provider, store, io = self.make(); seen = []
        def hook(raw, wire):
            if wire == b'STATUS':
                seen.append(wire)
                if len(seen) == 2:
                    io.sockets[1].queue.append((b'<3>CTRL-EVENT-DISCONNECTED bssid=02:aa:bb:cc:dd:ee reason=3',
                        [(1, 2, p._CRED.pack(300, 0, 0))], 0, provider._ctrl_endpoint[0]))
        io.command_hook = hook
        self.reject(lease, lambda: False, 'event_removed')
        self.assertEqual(2, len(seen)); self.assertIsNone(provider._connection.result)

    def test_source_inverse_preserves_v12_restore_caps_alias_and_all_old_defs(self):
        source = (CANDIDATE / 'mta_client_linux_provider.py').read_text(encoding='utf-8')
        original = (BASE / 'candidate/client-diagnostic-v12/runtime/mta_client_linux_provider.py').read_text(encoding='utf-8')
        source = source.replace('import mta_client_connection as connection\n', '', 1)
        source = source.replace('        self._connection = self._connection_event = self._connection_event_endpoint = None\n        self._connection_event_requested = False\n', '', 1)
        first = source.index('    def _connection_context'); end = source.index('    def request_child_stop', first)
        source = source[:first] + source[end:]
        first = source.index('    def connect_p2p'); end = source.index('    def _note_restore_diagnostic', first)
        source = source[:first] + source[end:]
        self.assertEqual(original, source)
        self.assertEqual('17e09c40d4c04c048b46e50de1151a97726086c0b43cace8a0c7e5fd3d7eb288', hashlib.sha256(original.encode()).hexdigest())
        self.assertIs(p.connection, c); self.assertIs(sys.modules['mta_client_connection'], old.c)
        self.assertFalse(p.LinuxClientInitProvider().status()['send_available'])
        for path in (CANDIDATE / 'mta_client_linux_provider.py', CANDIDATE / 'mta_client_connection.py', Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_connection_source_inverse_only_checkpoint_increment(self):
        source = (CANDIDATE / 'mta_client_connection.py').read_text(encoding='utf-8')
        original = (BASE / 'candidate/client-connection-v2/runtime/mta_client_connection.py').read_text(encoding='utf-8')
        replacements = (
            ('    def __init__(self, provider, lease, info, checkpoint=None):', '    def __init__(self, provider, lease, info):'),
            ('        self._cancel_checkpoint = checkpoint  # Exact synchronous F callback, not authority.\n', ''),
            ('    def _fresh(self, full=False):\n        self._checkpoint()', '    def _fresh(self, full=False):'),
            ('            self._checkpoint()\n            return value\n        self._checkpoint()', '            return value'),
            ('                self._checkpoint()\n                if self.provider.cancelled.is_set()', '                if self.provider.cancelled.is_set()'),
            ('                self.lease._restore_held = True  # restore must not acquire a second time.\n                self._checkpoint()\n',
             '                self.lease._restore_held = True  # restore must not acquire a second time.\n'))
        for new, prior in replacements:
            self.assertEqual(1, source.count(new)); source = source.replace(new, prior, 1)
        first = source.index('    def _checkpoint(self):'); end = source.index('    def _fresh(', first)
        source = source[:first] + source[end:]
        self.assertEqual(original, source)
        self.assertEqual('84ce100a1449a92562eec9e76b1b5d0bc28a490960fd381e701d29169e081ba3', hashlib.sha256(original.encode()).hexdigest())
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
