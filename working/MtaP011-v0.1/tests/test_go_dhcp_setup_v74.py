"""HOST74: seven new Server setup/first-service cases; SOURCE only.

The future HOST child executes the COMPLETE fixed Server74, mta_ip and
mta_dhcp definitions. No old TestCase/method or Bootstrap/Loader/GO graph is
imported. Native binding issuance, current/closure checks and UDP resources
are explicitly INERT MODELS. FakeSocket never creates an OS socket or FD.
Its Linux socket constants/ancillary helper are modeled, including on Windows;
inet_ntoa is the stdlib pure formatter, not a network operation.

The complete actual protocol core is only constructed (no DORA/pktinfo replay).
One deny-only malformed model binding causes its ORIGINAL constructor error.
Model source checks/issued caps/closed=True do NOT prove actual Native issuance,
kernel ingress, typed EBADF, restoration, radio, device, phone or readiness.
Platform IO tripwires must stay zero for EACH case, including caught failures.
This source was authored without executing, importing or AST checking it.
"""
import builtins
import collections
import hashlib
import io
import math
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import types
import unittest
from contextlib import ExitStack
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('mta_ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_dhcp', 'runtime/mta_dhcp.py', 15719,
     '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_go_dhcp', 'candidate/go-dhcp-setup-v74/runtime/mta_go_dhcp.py', 20912,
     '8ce808f217426667b7a45447a92a51f26e7021d5255bfe83c36a6906ae424290'))
MARKER = ('HOST74_DHCP_SETUP new_methods=1 old_methods=0 '
          'native_model=true device=false phone=false\n')


def _source_bytes():
    result = {}
    for name, path, size, digest in SOURCES:
        raw = (ROOT / path).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, digest):
            raise AssertionError('HOST74 fixed source changed')
        result[name] = raw
    return result


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST74 platform/RF IO forbidden')


def _tripwires(stack):
    targets = [(builtins, 'open'), (io, 'open'), (socket, 'socket'),
               (subprocess, 'Popen'), (select, 'select'),
               (threading.Thread, 'start')]
    for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'mkdir',
                 'unlink', 'rename', 'fork', 'execve', 'kill', 'urandom'):
        if hasattr(os, name):
            targets.append((os, name))
    return [stack.enter_context(mock.patch.object(owner, name,
            side_effect=_forbidden)) for owner, name in targets]


class _Clock(object):
    def __init__(self):
        self.value, self.calls = 1.0, 0
    def __call__(self):
        self.calls += 1
        return self.value


def _socket_model():
    """Explicit static Linux API model; no real socket factory is exposed."""
    module = types.ModuleType('socket')
    for name, value in (('AF_INET', 2), ('SOCK_DGRAM', 2), ('SOL_SOCKET', 1),
            ('SO_TYPE', 3), ('SO_REUSEADDR', 2), ('SO_BROADCAST', 6),
            ('IPPROTO_IP', 0)):
        setattr(module, name, value)
    module.timeout = socket.timeout
    module.inet_ntoa = socket.inet_ntoa  # Pure bytes formatter, no OS/FD.
    def model_cmsg_space(size):
        if type(size) is not int or size < 0:
            raise AssertionError('HOST74 ancillary model size')
        return 12 + ((size + 3) // 4) * 4  # Explicit ARM/Linux model only.
    module.CMSG_SPACE = model_cmsg_space
    module.socket = _forbidden
    return module


def _fixture(raws, case):
    """Complete fixed pure definitions plus an inert exact binding class.

    Source metadata/issuer checks below are only model identity checks. They
    cannot replace GoDhcpBinding/Native/resource tickets from a deployment.
    """
    events, setup_samples = [], []
    clock = _Clock()
    until = 15.0 if case == 'service_clamp' else 301.0
    setup = float(str(min(until, clock.value + 20.0)))
    mutex = threading.RLock()
    native_module = types.ModuleType('mta_go_native')
    sock_module = _socket_model()
    owner = types.SimpleNamespace(dhcp=None, worker=threading.current_thread())
    store, deployment = object(), object()

    class GoSourceError(ValueError):
        pass

    native_module.sources = types.SimpleNamespace(GoSourceError=GoSourceError)
    native_owner = types.SimpleNamespace(_scope=setup, owner=owner,
        _setup_until_original=setup, row=None, binding=None, server=None,
        issued_end=None, issued_ticket=None, issue_count=0,
        active_fetches=0, open_calls=0, close_calls=0, socket_checks=0,
        cancelled=False)

    class FakeSocket(object):
        """No fileno or actual FD; all options/bind/timeout/close are data."""
        def __init__(self):
            self.family, self.type = 2, 2
            self.options = {(1, 3): 2, (1, 2): 0, (1, 15): 0,
                            (1, 6): 0, (0, 8): 0}
            self.inheritable, self.timeout = True, None
            self.endpoint, self.closed = None, False
            self.recv_calls = self.send_calls = self.close_calls = 0
        def _record(self, method):
            server = owner.dhcp
            events.append(('fake_socket_' + method, clock.value))
            if server is not None and not server._open_returned:
                setup_samples.append((method, server._core, server._active_until,
                                      server._active_until_original))
        def setsockopt(self, level, option, value):
            self._record('setsockopt')
            self.options[(level, option)] = value
        def getsockopt(self, level, option, length=None):
            self._record('getsockopt')
            if option == 25:
                if length != 16:
                    raise AssertionError('HOST74 device readback length')
                return self.options[(level, option)]
            return self.options[(level, option)]
        def set_inheritable(self, value):
            self._record('set_inheritable')
            self.inheritable = value
        def get_inheritable(self):
            self._record('get_inheritable')
            return self.inheritable
        def settimeout(self, value):
            self._record('settimeout')
            if type(value) not in (int, float) or not 0 < value <= 0.2:
                raise AssertionError('HOST74 timeout not narrowed')
            self.timeout = value
        def gettimeout(self):
            self._record('gettimeout')
            return self.timeout
        def bind(self, endpoint):
            self._record('bind')
            if endpoint != ('0.0.0.0', 67) or self.endpoint is not None:
                raise AssertionError('HOST74 bind model changed')
            self.endpoint = endpoint
            # This explicit fake-OS delay models setup work, not elapsed HW.
            clock.value = setup if case == 'setup_expiry' else 9.0
        def getsockname(self):
            self._record('getsockname')
            return self.endpoint
        def recvmsg(self, length, ancillary_length, flags):
            self._record('recvmsg')
            self.recv_calls += 1
            if self.closed or flags != 0 or self.timeout is None:
                raise AssertionError('HOST74 idle receive model invalid')
            raise sock_module.timeout('HOST74 modeled idle timeout')
        def sendmsg(self, *args):
            self.send_calls += 1
            raise AssertionError('HOST74 no packet/send replay permitted')
        def close(self):
            self._record('close')
            self.close_calls += 1
            if self.closed:
                raise AssertionError('HOST74 repeated model raw close')
            self.closed = True

    class GoDhcpBinding(object):
        """INERT exact class used by Server's actual type/identity gates."""
        def __init__(self):
            self.native, self.owner, self.store = native_owner, owner, store
            self.deployment, self.worker = deployment, threading.current_thread()
            self.mutex, self.clock, self.until = mutex, clock, until
            self.setup_until = setup
            self.origin = types.SimpleNamespace(name='p2p-host74', ifindex=74)
            self.server_ip = 0xc0a83101
            # Deny-only malformed MODEL payload exercises the actual protocol
            # constructor's original error; real Native+1 issuance is NOT run.
            self.client_ip = self.server_ip if case == 'core_failure' else self.server_ip + 1
            self.subnet_mask = 0xffffff00
            self.originals = (self.native, self.owner, self.store, self.deployment,
                self.worker, self.mutex, self.clock, self.until, self.origin,
                self.server_ip, self.client_ip, self.subnet_mask, self.setup_until)
        def _original(self, server):
            if (self is not native_owner.binding or server is not native_owner.server or
                    owner.dhcp is not server or threading.current_thread() is not self.worker or
                    self.mutex._is_owned() is not True or
                    any(a is not b for a, b in zip((self.native, self.owner, self.store,
                        self.deployment, self.worker, self.mutex, self.clock,
                        self.until, self.origin), self.originals[:9])) or
                    (self.server_ip, self.client_ip, self.subnet_mask) != self.originals[9:12] or
                    self.setup_until is not native_owner._setup_until_original):
                raise GoSourceError('model_binding_changed')
        def check(self, server):
            self._original(server)
            now = clock()
            if native_owner.cancelled:
                raise GoSourceError('stop_requested')
            if now >= native_owner._scope or now >= self.until:
                raise GoSourceError('deadline')
            return now
        def active_until(self, server):
            self._original(server)
            native_owner.active_fetches += 1
            ticket = native_owner.issued_ticket
            if (ticket is None or type(ticket) is not tuple or
                    ticket != (native_owner, self, server, native_owner.issued_end) or
                    native_owner.issued_end is None):
                raise GoSourceError('model_service_not_issued')
            return native_owner.issued_end
        def cancelled(self, server):
            self._original(server)
            return native_owner.cancelled
        def open_socket(self, server):
            self._original(server)
            self.check(server)
            if native_owner.open_calls or native_owner.row is not None:
                raise GoSourceError('model_factory_repeated')
            native_owner.open_calls += 1
            row = types.SimpleNamespace(value=None, returned=False,
                close_attempted=False, closed=False, unknown=True)
            native_owner.row = row  # MODEL original row before fake factory.
            candidate = FakeSocket()
            row.value, row.returned, row.unknown = candidate, True, False
            events.append(('native_fake_factory_model', row, candidate))
            return candidate
        def socket_current(self, server, sock):
            self._original(server)
            native_owner.socket_checks += 1
            row = native_owner.row
            if row is None or row.value is not sock or row.unknown or sock.closed:
                raise GoSourceError('model_socket_changed')
            return True  # MODEL identity, not fstat/kernel/typed FD proof.
        def close_socket(self, server, sock):
            self._original(server)  # Stop-only; no active clock/expiry gate.
            row = native_owner.row
            if row is None or row.value is not sock or row.unknown or row.close_attempted:
                raise GoSourceError('model_close_source_changed')
            native_owner.close_calls += 1
            row.close_attempted = True
            sock.close()
            row.closed = True
            events.append(('native_fake_closed_model', row, sock))
            return True  # No actual once-close/EBADF is claimed.
        def admit_station(self, *args):
            raise AssertionError('HOST74 no station/DORA replay permitted')

    native_module.GoDhcpBinding = GoDhcpBinding
    ip_module = types.ModuleType('mta_ip')
    wire_module = types.ModuleType('mta_dhcp')
    server_module = types.ModuleType('mta_go_dhcp')
    modules = {'socket': sock_module, 'mta_go_native': native_module,
               'mta_ip': ip_module, 'mta_dhcp': wire_module,
               'mta_go_dhcp': server_module}
    with mock.patch.dict(sys.modules, modules):
        exec(compile(raws['mta_ip'], 'HOST74_fixed_mta_ip.py', 'exec'), ip_module.__dict__)
        exec(compile(raws['mta_dhcp'], 'HOST74_fixed_mta_dhcp.py', 'exec'), wire_module.__dict__)
        exec(compile(raws['mta_go_dhcp'], 'HOST74_fixed_server.py', 'exec'), server_module.__dict__)
    binding = GoDhcpBinding()
    native_owner.binding = binding

    def issue_once_model(server):
        # Models Native having completed its final actual-boundary checks; no
        # real Native readback/canonical or network admission is signed here.
        binding._original(server)
        if (native_owner.issue_count or server._open_returned is not True or
                server.socket is not native_owner.row.value or
                server._setup_until_original is not setup or clock.value >= setup):
            raise GoSourceError('model_service_issue_repeated_or_late')
        events.append(('native_final_boundary_model', server, clock.value))
        end = min(binding.until, clock.value + 20.0)
        native_owner.issue_count += 1
        native_owner.issued_end = end
        native_owner.issued_ticket = (native_owner, binding, server, end)
        native_owner._scope = end
        events.append(('native_first_service_cap_model', end))
        return end

    return types.SimpleNamespace(modules=modules, server_module=server_module,
        ip=ip_module, wire=wire_module, binding=binding, native=native_owner,
        owner=owner, mutex=mutex, clock=clock, setup=setup, until=until,
        error=GoSourceError, issue_once=issue_once_model,
        events=events, setup_samples=setup_samples)


class GoDhcpSetup74Test(unittest.TestCase):
    def test_setup_and_first_service_scope(self):
        raws = _source_bytes()  # Fixed SOURCE reads precede platform tripwires.
        cases = ('delayed_setup', 'unstarted_server', 'setup_expiry',
                 'cap_not_issued', 'service_clamp', 'core_failure',
                 'setup_reference_changed')
        completed = []
        with ExitStack() as stack:
            probes = _tripwires(stack)
            for case in cases:
                with self.subTest(case=case):
                    f = _fixture(raws, case)
                    with mock.patch.dict(sys.modules, f.modules), f.mutex:
                        # Complete ACTUAL Server constructor; only binding is
                        # inert. Strong original returned object is registered.
                        s = f.server_module.GoDhcpServer(f.binding)
                        f.owner.dhcp = f.native.server = s
                        original_setup = s._setup_until_original
                        self.assertIs(original_setup, f.setup)
                        self.assertIs(s._setup_until, f.binding.setup_until)
                        self.assertIsNone(s._core)
                        self.assertIsNone(s._active_until)
                        self.assertFalse(s._service_called)
                        self.assertEqual(0, f.native.open_calls)
                        self.assertEqual(0, f.native.issue_count)
                        if case == 'setup_expiry':
                            with self.assertRaises(f.error) as caught:
                                s.open()
                            self.assertEqual('deadline', str(caught.exception))
                            self.assertIs(s._failure, caught.exception)
                            self.assertEqual(f.setup, f.clock.value)
                            self.assertFalse(s._open_returned)
                            self.assertFalse(s._opening)
                            self.assertEqual('failed', s._stage)
                            self.assertIsNone(s._core)
                            self.assertIsNone(s._active_until)
                            self.assertEqual(0, f.native.issue_count)
                            self.assertEqual(0, f.native.active_fetches)
                            self.assertIs(s.socket, f.native.row.value)
                            self.assertEqual(('0.0.0.0', 67), s.socket.endpoint)
                            self._assert_model_close(f, s)
                        else:
                            self.assertIs(s.open(), s)
                            self.assertEqual(9.0, f.clock.value)
                            self.assertEqual('listening', s._stage)
                            self.assertTrue(s._open_returned)
                            self.assertFalse(s._opening)
                            self.assertIsNone(s._core)
                            self.assertIsNone(s._active_until)
                            self.assertIsNone(s._active_until_original)
                            self.assertFalse(s._service_called)
                            self.assertEqual(1, f.native.open_calls)
                            self.assertEqual(0, f.native.active_fetches)
                            self.assertEqual(0, f.native.issue_count)
                            original_socket = s.socket
                            if case == 'unstarted_server':
                                with self.assertRaises(f.server_module.GoDhcpError) as caught:
                                    s.serve_once()
                                self.assertEqual('dhcp_poll_invalid', str(caught.exception))
                                self.assertIsNone(s.allocation())
                                self.assertEqual(0, original_socket.recv_calls)
                                self.assertEqual(0, original_socket.send_calls)
                                self.assertIsNone(s._failure)
                                self.assertFalse(s._service_called)
                                self.assertEqual(0, f.native.issue_count)
                                self._assert_model_close(f, s)
                            elif case == 'cap_not_issued':
                                with self.assertRaises(f.error) as caught:
                                    s.start_service()
                                failure = caught.exception
                                self.assertEqual('model_service_not_issued', str(failure))
                                self.assertIs(s._failure, failure)
                                self.assertTrue(s._service_called)
                                self.assertIsNone(s._core)
                                self.assertIsNone(s._active_until)
                                self.assertEqual(1, f.native.active_fetches)
                                self.assertEqual(0, f.native.issue_count)
                                # Deny-only late model issuance must not make
                                # the actual once-attempt Server start retryable.
                                end = f.issue_once(s)
                                with self.assertRaises(f.server_module.GoDhcpError) as second:
                                    s.start_service()
                                self.assertEqual('dhcp_service_already_attempted', str(second.exception))
                                self.assertIs(s._failure, failure)
                                self.assertIsNone(s._core)
                                self.assertEqual(1, f.native.active_fetches)
                                self.assertEqual(1, f.native.issue_count)
                                self.assertIs(f.native.issued_end, end)
                                self._assert_model_close(f, s)
                            elif case == 'setup_reference_changed':
                                changed = float(str(f.setup))
                                self.assertEqual(changed, f.setup)
                                self.assertIsNot(changed, f.setup)
                                f.binding.setup_until = changed  # Foreign ref MODEL fault.
                                with self.assertRaises(f.server_module.GoDhcpError) as caught:
                                    s.start_service()
                                self.assertEqual('dhcp_setup_scope_changed', str(caught.exception))
                                self.assertFalse(s._service_called)
                                self.assertIsNone(s._failure)
                                self.assertIsNone(s._core)
                                self.assertIsNone(s._active_until)
                                # No close of a changed/foreign owner source,
                                # even though its old fake socket is retained.
                                with self.assertRaises(f.server_module.GoDhcpError) as close:
                                    s.close()
                                self.assertEqual('dhcp_setup_scope_changed', str(close.exception))
                                self.assertFalse(s._close_called)
                                self.assertEqual(0, f.native.close_calls)
                                self.assertEqual(0, original_socket.close_calls)
                                self.assertFalse(original_socket.closed)
                                self.assertIs(s.socket, original_socket)
                            else:
                                end = f.issue_once(s)
                                self.assertEqual(1, f.native.issue_count)
                                self.assertIs(f.native.issued_end, end)
                                self.assertEqual(15.0 if case == 'service_clamp' else 29.0, end)
                                self.assertLessEqual(end, f.binding.until)
                                self.assertIs(s._setup_until_original, original_setup)
                                if case == 'core_failure':
                                    # Uses the actual fixed wire constructor;
                                    # no monkeypatched constructor or old DORA.
                                    with self.assertRaises(f.wire.DhcpError) as caught:
                                        s.start_service()
                                    failure = caught.exception
                                    self.assertEqual('server_and_client_address_equal', str(failure))
                                    self.assertIs(s._failure, failure)
                                    self.assertTrue(s._service_called)
                                    self.assertIs(s._active_until, end)
                                    self.assertIs(s._active_until_original, end)
                                    self.assertIsNone(s._core)
                                    self.assertIs(s.socket, original_socket)
                                    self.assertEqual('failed', s._stage)
                                    with self.assertRaises(f.server_module.GoDhcpError) as second:
                                        s.start_service()
                                    self.assertEqual('dhcp_service_already_attempted', str(second.exception))
                                    self.assertIs(s._failure, failure)
                                    self.assertEqual(1, f.native.active_fetches)
                                    self.assertEqual(1, f.native.issue_count)
                                    with self.assertRaises(f.error):
                                        f.issue_once(s)
                                    self.assertIs(f.native.issued_end, end)
                                    self._assert_model_close(f, s)
                                else:
                                    self.assertIs(s.start_service(), s)
                                    self.assertTrue(s._service_called)
                                    self.assertEqual('serving', s._stage)
                                    self.assertIs(s._active_until, end)
                                    self.assertIs(s._active_until_original, end)
                                    self.assertIs(type(s._core), f.wire.SingleClientServer)
                                    self.assertEqual(end, s._core.deadline)
                                    self.assertEqual(1, f.native.active_fetches)
                                    self.assertIs(s.socket, original_socket)
                                    if case == 'service_clamp':
                                        self.assertEqual(15.0, f.setup)
                                        self.assertEqual(15.0, f.until)
                                        self.assertIs(end, f.binding.until)
                                    # No packets: only the new idle-service
                                    # boundary is exercised, no old envelopes.
                                    issued_ticket = f.native.issued_ticket
                                    f.clock.value = 10.0
                                    self.assertEqual({'event': 'idle', 'reason': 'no_packet'}, s.serve_once())
                                    self.assertEqual(1, original_socket.recv_calls)
                                    self.assertEqual(0, original_socket.send_calls)
                                    self.assertIsNone(s.allocation())
                                    self.assertIs(s._active_until_original, end)
                                    self.assertIs(f.native._scope, end)
                                    self.assertIs(f.native.issued_ticket, issued_ticket)
                                    self.assertEqual(1, f.native.issue_count)
                                    self.assertEqual(1, f.native.active_fetches)
                                    self.assertEqual(end, s._core.deadline)
                                    f.clock.value = end
                                    self.assertEqual({'event': 'finished',
                                        'reason': 'original_service_stopped'}, s.serve_once())
                                    self.assertEqual(1, original_socket.recv_calls)
                                    self.assertIs(f.native.issued_ticket, issued_ticket)
                                    self.assertEqual(1, f.native.issue_count)
                                    self._assert_model_close(f, s)
                        self.assertGreater(len(f.setup_samples), 0)
                        # Every fake socket setup call observed no core/cap;
                        # setting socket options alone cannot start the service.
                        for method, core, active_end, original_end in f.setup_samples:
                            self.assertIsNone(core, method)
                            self.assertIsNone(active_end, method)
                            self.assertIsNone(original_end, method)
                        self.assertIs(s.socket, s._socket_original)
                        self.assertIs(s.binding, f.binding)
                        self.assertIs(s._setup_until_original, original_setup)
                        self.assertEqual(0, s.socket.send_calls)
                        status = s.status()
                        for name in ('phone_configured', 'default_route_supplied',
                                     'dns_supplied', 'dhcp_ready', 'send_ready'):
                            self.assertIs(status[name], False)
                    for probe in probes:
                        self.assertEqual(0, probe.call_count)
                    completed.append(case)
            self.assertEqual(list(cases), completed)
            self.assertEqual(7, len(completed))
            for probe in probes:
                self.assertEqual(0, probe.call_count)
        sys.stdout.write(MARKER)

    def _assert_model_close(self, f, server):
        # Actual Server.close orchestration, INERT Native/raw closure result.
        # No Linux descriptor/EBADF or restored radio assertion is made.
        sock = server.socket
        self.assertIs(server.close(), True)
        self.assertIs(server._closed, True)
        self.assertEqual(1, f.native.close_calls)
        self.assertEqual(1, sock.close_calls)
        self.assertTrue(sock.closed)
        self.assertTrue(f.native.row.close_attempted)
        self.assertTrue(f.native.row.closed)
        self.assertIs(server.socket, sock)
        self.assertIs(server._socket_original, sock)
        self.assertIs(server.close(), True)
        self.assertEqual(1, f.native.close_calls)
        self.assertEqual(1, sock.close_calls)


if __name__ == '__main__':
    unittest.main()
