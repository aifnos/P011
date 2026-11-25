"""Only v2 event revocation cases, real candidate methods over old FakeIO.

Saved child actors are synthetic; no actual association, FD, RF or restoration
is validated. Old fixture globals are copied, never monkey-patched in place.
"""
import ast
import hashlib
import importlib.util
import sys
import types
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_connection as old
from test_client_files import PENDING

CANDIDATE = BASE / 'candidate/client-connection-v2/runtime'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


c = load('client_connection_v2_private', CANDIDATE / 'mta_client_connection.py')
saved = sys.modules.get('mta_client_connection')
sys.modules['mta_client_connection'] = c
try:
    p = load('client_connection_v2_provider_private', CANDIDATE / 'mta_client_linux_provider.py')
finally:
    if saved is None: del sys.modules['mta_client_connection']
    else: sys.modules['mta_client_connection'] = saved


def fixture(function, changes):
    namespace = dict(function.__globals__)
    namespace.update(changes)
    return types.FunctionType(function.__code__, namespace, function.__name__,
        function.__defaults__, function.__closure__)


make_manifest = fixture(old.manifest, {'p': p})
DISCONNECTED = b'<3>CTRL-EVENT-DISCONNECTED bssid=02:aa:bb:cc:dd:ee reason=3 locally_generated=0'


class ConnectionV2Tests(unittest.TestCase):
    setUp = fixture(old.ConnectionTests.setUp, {'p': p})
    make = fixture(old.ConnectionTests.make, {'p': p, 'c': c, 'manifest': make_manifest})

    def packet(self, provider, raw=DISCONNECTED):
        return (raw, [(1, 2, p._CRED.pack(300, 0, 0))], 0, provider._ctrl_endpoint[0])

    def after_status(self, io, provider, number):
        seen = []
        def hook(raw, wire):
            if wire == b'STATUS':
                seen.append(wire)
                if len(seen) == number: io.sockets[1].queue.append(self.packet(provider))
        io.command_hook = hook
        return seen

    def assert_retained(self, lease, store, io):
        self.assertTrue(lease.provider._connection.failed)
        self.assertFalse(lease.cleanup_complete)
        self.assertEqual('client_init_ready', store.current(lease.locks).stage)
        self.assertIn(PENDING, io.nodes)
        self.assertEqual(0, sum(raw.close_calls for raw in io.sockets))
        self.assertFalse(lease.provider.status()['send_available'])
        self.assertFalse(lease.provider.status()['receive_available'])

    def test_run_final_drain_disconnect_revokes_even_two_completed_status(self):
        lease, provider, store, io = self.make()
        statuses = self.after_status(io, provider, 2)
        with self.assertRaises(c.ConnectionError) as error: lease.connect_p2p(old.info())
        self.assertEqual('event_removed', error.exception.code)
        self.assertEqual(2, len(statuses))
        self.assertIsNone(provider._connection.result)
        self.assertEqual([], provider._connection.observations)
        self.assertEqual(DISCONNECTED, provider._connection._events[-1])
        self.assert_retained(lease, store, io)

    def test_readback_final_drain_disconnect_revokes_existing_observation(self):
        lease, provider, store, io = self.make()
        first = lease.connect_p2p(old.info())
        statuses = self.after_status(io, provider, 2)
        with self.assertRaises(c.ConnectionError) as error: lease.read_connection(first)
        self.assertEqual('event_removed', error.exception.code)
        self.assertEqual(2, len(statuses))
        self.assertIs(first, provider._connection.result)
        self.assertEqual([first], provider._connection.observations)
        with self.assertRaises(c.ConnectionError) as repeat: lease.read_connection(first)
        self.assertEqual('not_connected', repeat.exception.code)
        self.assert_retained(lease, store, io)

    def test_before_group_disconnect_remains_information_not_association(self):
        lease, provider, store, io = self.make()
        io.queue_event = [self.packet(provider), self.packet(provider, old.GROUP)]
        observed = lease.connect_p2p(old.info())
        self.assertIs(type(observed), c.ConnectionObservation)
        self.assertEqual('information', c._event(DISCONNECTED, old.OWNED.name.encode('ascii'))[0])
        self.assertFalse(provider._connection.failed)
        self.assertFalse(observed.public_summary()['dhcp_proof_issued'])

    def test_disconnecting_true_accepts_expected_disconnected_event(self):
        lease, provider, store, io = self.make()
        first = lease.connect_p2p(old.info())
        def hook(raw, wire):
            if wire == b'DISCONNECT': io.sockets[1].queue.append(self.packet(provider))
        io.command_hook = hook
        result = lease.disconnect_p2p()
        self.assertTrue(result['disconnect_observed'])
        self.assertFalse(result['restored'])
        self.assertFalse(provider._connection.failed)
        self.assertEqual(DISCONNECTED, provider._connection._events[-1])
        with self.assertRaises(c.ConnectionError): lease.read_connection(first)
        self.assertEqual('client_init_ready', store.current(lease.locks).stage)

    test_original_disconnect_method_on_v2 = fixture(
        old.ConnectionTests.test_disconnect_is_observation_not_restore_or_completion,
        {'p': p, 'c': c})

    def test_exact_two_line_diff_provider_original_and_python35(self):
        old_source = (BASE / 'candidate/client-connection/runtime/mta_client_connection.py').read_bytes()
        new_source = (CANDIDATE / 'mta_client_connection.py').read_bytes()
        addition = (b"            if self.group is not None and not disconnecting and value.startswith(b'CTRL-EVENT-DISCONNECTED '):\n"
            b"                _fail('event_removed')\n")
        self.assertEqual(1, new_source.count(addition))
        self.assertEqual(old_source, new_source.replace(addition, b''))
        self.assertEqual('584a8007b076cb1df41697c690268e0d31dc0148b1eaeff43591403de00d10a4', hashlib.sha256(old_source).hexdigest())
        provider = (CANDIDATE / 'mta_client_linux_provider.py').read_bytes()
        self.assertEqual(provider, (BASE / 'candidate/client-connection/runtime/mta_client_linux_provider.py').read_bytes())
        self.assertEqual('41459a480e9d78924a792bd881d25cd0696d64f0637a9d4b9be06083af09d25b', hashlib.sha256(provider).hexdigest())
        self.assertIs(p.connection, c)
        self.assertIs(sys.modules['mta_client_connection'], old.c)
        for source in (new_source, provider, Path(__file__).read_bytes()):
            ast.parse(source.decode('utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
