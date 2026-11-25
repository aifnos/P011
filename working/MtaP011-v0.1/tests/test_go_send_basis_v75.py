"""HOST75: only new send-basis/listener algorithms, not a GO grant.

The future ROOT-only child loads the WHOLE fixed Native75 source definition.
New codecs, immutable products, once flags and native FD inventory/close code
are actual production algorithms. Existing GO owner/durable/group/IP/DHCP
boundaries are explicit inert fixtures; no full Loader, Store publication,
bootstrap, DHCP, RF, real socket, peer or restoration success is asserted.
Socket syscalls/fstat/EBADF are modeled, not Linux/P011 kernel evidence.
No old TestCase, old test method or old complete native lifecycle is executed.

The author only wrote/read/hashed this source. ROOT alone may execute it.
"""
import builtins
import errno
import hashlib
import io
import math
import os
from pathlib import Path
import select
import socket
import stat
import struct
import subprocess
import threading
import types
import unittest
from contextlib import ExitStack
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('candidate/go-send-basis-v75/runtime/mta_go_native.py',
          '25ba2d2b5c9f810242fe3f0e84dce891c7ac57b2ac2058af93492f247486b435',
          168493)
MARKER = ('HOST75_SEND_BASIS new_methods=1 old_methods=0 '
          'os_model=true device=false phone=false\n')


def _source_bytes():
    if type(SOURCE) is not tuple or len(SOURCE) != 3:
        raise AssertionError('HOST75 source not frozen')
    raw = (ROOT / SOURCE[0]).read_bytes()
    if len(raw) != SOURCE[2] or hashlib.sha256(raw).hexdigest() != SOURCE[1]:
        raise AssertionError('HOST75 fixed Native source changed')
    return raw


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST75 platform/RF IO forbidden')


def _tripwires(stack):
    targets = [(builtins, 'open'), (io, 'open'), (socket, 'socket'),
               (subprocess, 'Popen'), (select, 'select'),
               (threading.Thread, 'start')]
    for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'mkdir',
                 'unlink', 'rename', 'fork', 'execve', 'kill'):
        if hasattr(os, name): targets.append((os, name))
    return [stack.enter_context(mock.patch.object(owner, name,
            side_effect=_forbidden)) for owner, name in targets]


class _Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class _SourceForest(object):
    """Private definition domain; inert imported classes are NOT fixed GO20.

    No imported fake method can grant Native/Store readiness. Only the explicit
    preexisting-boundary seams installed by _Fixture may be called. All new75
    and original FD inventory/check/close methods remain actual definitions.
    """
    def __init__(self, raw):
        self.modules = {}
        for name in ('mta_client_resource_budget', 'mta_client_proc',
                     'mta_go_executor', 'mta_go_bootstrap_store', 'mta_ip',
                     'mta_ip_lease', 'mta_p2p_client_init', 'mta_go_deployment',
                     'mta_go_bootstrap', 'mta_go_dhcp'):
            self.modules[name] = types.ModuleType(name)

        class GoSourceError(Exception):
            def __init__(self, code):
                self.code = code
                Exception.__init__(self, code)
        source = self.modules['mta_go_deployment']
        source.GoSourceError = GoSourceError
        source.LoadedGoDeployment = type('LoadedGoDeployment', (), {})
        source._uint = lambda value: type(value) is int and 0 <= value < 2**64
        def model_time(value):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value < 1e12:
                raise GoSourceError('model_time_invalid')
            return float(value)
        source._time = model_time
        source._LinuxIo = type('_LinuxIo', (), {'validate': _forbidden})

        for name, cls_name, method in (
                ('mta_client_resource_budget', 'ResourceBudget', '_context'),
                ('mta_client_proc', 'ProcReader', 'owns_generation'),
                ('mta_go_executor', 'GoEntrySource', '_context'),
                ('mta_go_bootstrap_store', 'GoBootstrapStore', '_owner')):
            setattr(self.modules[name], cls_name,
                    type(cls_name, (), {method: _forbidden}))
        self.modules['mta_client_proc'].parse_stat = _forbidden
        self.modules['mta_go_bootstrap'].GoBootstrap = type(
            'GoBootstrap', (), {'_cancelled': lambda owner, until: owner.stop_requested})
        self.modules['mta_go_dhcp'].GoDhcpServer = type('GoDhcpServer', (), {})
        self.modules['mta_go_bootstrap_store'].GoCanonical = type('GoCanonical', (), {})
        self.modules['mta_go_bootstrap_store'].GoIpFacts = type('GoIpFacts', (), {})
        self.modules['mta_go_bootstrap_store'].GoDhcpFacts = type('GoDhcpFacts', (), {})
        self.modules['mta_ip'].AckResult = type('AckResult', (), {})
        self.modules['mta_ip'].RTM_NEWADDR = 20
        self.modules['mta_ip'].ipv4_text = lambda value: '.'.join(
            str((value >> shift) & 255) for shift in (24, 16, 8, 0))
        self.modules['mta_go_dhcp'].SO_BINDTODEVICE = 25
        self.modules['mta_go_dhcp'].SO_REUSEPORT = 15
        self.modules['mta_go_dhcp'].IP_PKTINFO = 8
        self.modules['mta_go_dhcp'].wire = types.SimpleNamespace(
            SingleClientServer=type('SingleClientServer', (), {}))
        self.modules['mta_go_dhcp'].GoDhcpServer._context = lambda server: server.model_context()
        class Origin(object):
            def __init__(self, phy, wdev, ifindex, name, iftype):
                self.phy, self.wdev, self.ifindex = phy, wdev, ifindex
                self.name, self.iftype = name, iftype
            def key(self): return self.phy, self.wdev, self.ifindex, self.name, self.iftype
        self.modules['mta_p2p_client_init'].Origin = Origin

        original_import = builtins.__import__
        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in self.modules and not level: return self.modules[name]
            if level or name.startswith(('mta_', 'p011_')):
                raise AssertionError('HOST75 undeclared private import')
            return original_import(name, globals, locals, fromlist, level)
        module = types.ModuleType('HOST75_actual_native')
        module.__file__ = str(ROOT / SOURCE[0])
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        self.native = module
        self.modules['mta_go_native'] = module
        exec(compile(raw, 'HOST75_fixed_native_definition', 'exec'), module.__dict__)


class _Raw(object):
    """Modeled TCP only; never listen/accept/connect or real networking."""
    def __init__(self, io_owner, fault=None, kind='tcp'):
        self.io, self.fd, self.fault = io_owner, io_owner.next_fd, fault
        self.kind = kind
        io_owner.next_fd += 1
        self.closed, self.close_calls = False, 0
        self.address, self.inheritable, self.blocking = None, True, True
        self.options = {}
        self.calls = []
        io_owner.raws.append(self)
    def fileno(self):
        self.calls.append(('fileno',))
        if self.io.native is not None:
            matching = [r for r in self.io.native.rows if r.value is self]
            self.io.fileno_retained.append(len(matching) == 1 and matching[0].returned is True)
        if self.fault == 'fileno': raise OSError(errno.EIO, 'model_fileno')
        return -1 if self.closed else self.fd
    def set_inheritable(self, value):
        self.calls.append(('set_inheritable', value)); self.inheritable = value
    def get_inheritable(self): return self.inheritable
    def setblocking(self, value):
        self.calls.append(('setblocking', value)); self.blocking = value
    def getblocking(self): return self.blocking
    def gettimeout(self): return None if self.blocking else 0.0
    def settimeout(self, value):
        self.calls.append(('settimeout', value)); self.blocking = value is None
    def setsockopt(self, level, option, value):
        self.calls.append(('setsockopt', level, option, value))
        self.options[(level, option)] = value
    def getsockopt(self, level, option, *args):
        self.calls.append(('getsockopt', level, option))
        if option == socket.SO_TYPE:
            return int(socket.SOCK_DGRAM if self.kind == 'udp' else socket.SOCK_STREAM)
        if option == 39: return int(socket.AF_INET)
        if option == 38: return int(socket.IPPROTO_TCP)
        return self.options.get((level, option), 0)
    def bind(self, endpoint):
        self.calls.append(('bind', endpoint)); self.address = (endpoint[0], 32123)
        if self.fault == 'late_bind': self.io.clock.value = self.io.end
    def getsockname(self):
        self.calls.append(('getsockname',)); return self.address
    def getpeername(self):
        self.calls.append(('getpeername',)); raise OSError(errno.ENOTCONN, 'model_unconnected')
    def listen(self, *args): raise AssertionError('HOST75 listener must not listen yet')
    def accept(self, *args): raise AssertionError('HOST75 no peer IO')
    def connect(self, *args): raise AssertionError('HOST75 no peer IO')
    def close(self):
        self.close_calls += 1; self.calls.append(('close',)); self.closed = True
        if self.fault == 'close_unknown': raise OSError(errno.EIO, 'model_close_return_unknown')
        return None


class _ModelIo(object):
    def __init__(self, clock):
        self.clock, self.end, self.next_fd = clock, 21.0, 70
        self.raws, self.factories = [], []
        self.fileno_retained = []
        self.native, self.fault = None, None
    def tcp(self):
        # This observation is before the raw returns; producer must register.
        self.factories.append(tuple(self.native.rows))
        if self.fault == 'factory': raise OSError(errno.EMFILE, 'model_factory_refusal')
        return _Raw(self, self.fault)
    def fstat(self, fd):
        rows = [r for r in self.raws if r.fd == fd]
        if len(rows) != 1 or rows[0].closed: raise OSError(errno.EBADF, 'model_bad_fd')
        return types.SimpleNamespace(st_dev=5, st_ino=1000+fd,
            st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_rdev=0)
    def validate(self): raise AssertionError('HOST75 no actual platform validate')


def _event(ssid=b'DIRECT-model', credentials=None):
    """Private deterministic fixture, never a captured phone/GO credential."""
    if credentials is None: credentials = b'psk=' + b'12'*32
    return (b'P2P-GROUP-STARTED mta01234567 GO ssid="' + ssid +
            b'" freq=2412 ' + credentials + b' go_dev_addr=02:11:22:33:44:55\n')


def _credential_cases(test, module):
    escaped = b'DIRECT-\\xe4\\xb8\\xad\\xe6\\x96\\x87\\"\\\\'
    expected_ssid = 'DIRECT-中文"\\'
    phrase = b'model passphrase'
    derived = hashlib.pbkdf2_hmac('sha1', phrase, b'DIRECT-model', 4096, 32).hex().encode('ascii')
    valid = (
        (_event(), 'DIRECT-model', '12'*32),
        (_event(credentials=b'passphrase="'+phrase+b'"'), 'DIRECT-model', phrase.decode('ascii')),
        (_event(credentials=b'psk='+derived+b' passphrase="'+phrase+b'"'), 'DIRECT-model', phrase.decode('ascii')),
        (_event(escaped), expected_ssid, '12'*32),
    )
    for ordinal, (raw, ssid, secret) in enumerate(valid):
        with test.subTest(layer='pure_codec_valid', case=ordinal):
            value = module._go_credentials_v75(raw, 'mta01234567', 2412)
            test.assertIs(type(value), module._GoCredentialsV75)
            test.assertIs(type(value.ssid), str)
            test.assertEqual(ssid, value.ssid)
            test.assertEqual(ssid.encode('utf-8'), value.ssid_bytes)
            test.assertEqual(secret, value.psk)
            test.assertEqual(bytes((2, 17, 34, 51, 68, 85)), value.go_dev_addr)
            with test.assertRaises(AttributeError): value.psk = 'not_a_cap'
            test.assertNotIn(secret, repr(value))
    normal = _event()
    invalid = (
        normal.replace(b'freq=2412', b'freq=2412 freq=2412'),
        normal.replace(b' GO ', b' client '),
        normal.replace(b'mta01234567', b'mta76543210'),
        normal.replace(b'02:11:', b'03:11:'),
        normal.replace(b'02:11:22:33:44:55', b'00:00:00:00:00:00'),
        _event(b'\\xff'),
        _event(b'\\x41'),  # Noncanonical vendor escaping of a printable ASCII byte.
        normal.replace(b'freq=2412', b'freq=2437'),
        normal + b'\0',
        normal + b'P2P-GROUP-STARTED foreign\n',
        _event(credentials=b'psk=12'),
        _event(credentials=b'passphrase="short"'),
        _event(credentials=b'psk='+b'12'*32+b' passphrase="'+phrase+b'"'),
        normal.replace(b'freq=2412', b'unknown=1 freq=2412'),
        _event(b'\\x00'),
    )
    for ordinal, raw in enumerate(invalid):
        with test.subTest(layer='pure_codec_refusal', case=ordinal):
            with test.assertRaises(module.sources.GoSourceError) as caught:
                module._go_credentials_v75(raw, 'mta01234567', 2412)
            test.assertEqual('native_send_credentials_invalid', caught.exception.code)
    with mock.patch.object(module.hashlib, 'pbkdf2_hmac', None):
        with test.assertRaises(module.sources.GoSourceError) as caught:
            module._go_credentials_v75(valid[2][0], 'mta01234567', 2412)
        test.assertEqual('native_send_kdf_unavailable', caught.exception.code)
    return len(valid), len(invalid)+1


class _Fixture(object):
    """Synthetic serving boundary, not real GO/IP/DHCP issuance.

    Complete Native ctor/new75/FD algorithms execute. Old _owner, _durable,
    _ip_original, full ip_current, _dhcp_owner and controller/STATUS exchange
    are explicit preexisting boundary seams. The synthetic canonical/ACK/UDP
    facts below can ONLY exercise new send-basis logic; they are not producers
    of any real authority. No Store.reserve/CAS/Loader authentication is called.
    """
    def __init__(self, forest):
        self.forest, self.module = forest, forest.native
        self.clock = _Clock()
        self.until, self.end, self.setup = 301.0, 21.0, 11.0
        self.worker, self.mutex = threading.current_thread(), threading.RLock()
        self.io = _ModelIo(self.clock)
        self.events = []
        m = forest.modules
        self.owner = m['mta_go_bootstrap'].GoBootstrap()
        self.store = m['mta_go_bootstrap_store'].GoBootstrapStore()
        self.deployment = m['mta_go_deployment'].LoadedGoDeployment()
        self.entry = types.SimpleNamespace(clock=self.clock, until=self.until,
            accounting=types.SimpleNamespace(_io_deadline=4.0))
        for name, value in (('until', self.until), ('worker', self.worker),
                ('mutex', self.mutex), ('clock', self.clock), ('owner', self.owner),
                ('issuer', object()), ('restore_attempted', False),
                ('restore_until', None), ('publication_unknown', False), ('failure', None)):
            setattr(self.store, name, value)
        self.deployment.modules = m
        for name, value in (('store', self.store), ('deployment', self.deployment),
                ('entry', self.entry), ('stop_requested', False),
                ('service_until', self.end), ('_service_until_original', self.end)):
            setattr(self.owner, name, value)
        self.native = self.module.NativeGoResources(self.owner, _io=self.io)
        self.owner.native = self.io.native = self.native
        n = self.native

        def old_owner(actual):
            self.events.append('inert_owner')
            if threading.current_thread() is not self.worker or actual.worker is not self.worker or \
                    any(a is not b for a, b in zip((self.owner, self.store, self.deployment,
                        self.until, self.worker, self.mutex, self.clock, self.entry, self.io), actual._originals)) or \
                    actual.rows is not actual._rows_original or tuple(actual.rows) != actual._history:
                raise self.module.sources.GoSourceError('native_owner_changed')
        n._owner = types.MethodType(old_owner, n)
        n._begin(self.end)

        self.origin = m['mta_p2p_client_init'].Origin(0, 8, 12, 'mta01234567', 9)
        self.address = types.SimpleNamespace(model_address='synthetic_owned_ip')
        key = (self.origin.key(), 0xc0a83101, 24, self.until)
        facts = m['mta_go_bootstrap_store'].GoIpFacts()
        facts.origin, facts.spec, facts.address = self.origin, types.SimpleNamespace(address=0xc0a83101), self.address
        facts.phase, facts.source_key = 'receipt_recorded', lambda: key
        confirmed = m['mta_go_bootstrap_store'].GoIpFacts()
        confirmed.origin, confirmed.spec, confirmed.address = facts.origin, facts.spec, facts.address
        confirmed.phase, confirmed.source_key = 'confirmed', lambda: key
        self.ip_intent = self.module.GoIpObservation(n, facts)
        n.ip_intent = self.ip_intent
        n.ip_receipt = self.module.GoIpObservation(n, facts)
        n.observations.extend((self.ip_intent, n.ip_receipt))
        ack = m['mta_ip'].AckResult()
        ack.command, ack.success = m['mta_ip'].RTM_NEWADDR, True
        n.ip_ack = n._ip_ack_original = ack
        n._ip_create_called = True
        n._ip_original = types.MethodType(lambda actual: self.ip_intent, n)

        self.group = self.module.GoGroupObservation(n, _event(),
            b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\n', 2412, self.origin)
        n.group, n.owned = self.group, self.origin
        self.canonical = m['mta_go_bootstrap_store'].GoCanonical()
        self.canonical.issuer = self.store.issuer
        self.canonical.record = types.SimpleNamespace(phase='dhcp_listening', ip=confirmed,
            dhcp=types.SimpleNamespace(phase='listening'))
        self.store.current, self.store._canonical_history = self.canonical, (self.canonical,)
        n._dhcp_setup_c2, n._dhcp_setup_h2 = self.canonical, self.store._canonical_history
        n._dhcp_setup_until_original = self.setup

        # Actual record/adopt/fd_current for modeled preexisting IP/UDP rows.
        n.ip_row = n._record('netlink', True)
        ip_raw = _Raw(self.io, kind='udp')
        n._adopt(n.ip_row, ip_raw, ip_raw.fileno())
        n.dhcp_row = n._dhcp_row_original = n._record('udp', True)
        self.udp = _Raw(self.io, kind='udp')
        self.udp.address, self.udp.inheritable = ('0.0.0.0', 67), False
        self.udp.options = {(socket.SOL_SOCKET, 25): b'mta01234567\0',
            (socket.SOL_SOCKET, socket.SO_REUSEADDR): 0, (socket.SOL_SOCKET, 15): 0,
            (socket.SOL_SOCKET, socket.SO_BROADCAST): 1, (socket.IPPROTO_IP, 8): 1}
        n._adopt(n.dhcp_row, self.udp, self.udp.fileno())
        n.dhcp_binding = self.module.GoDhcpBinding(n, n.ip_receipt)
        self.server = m['mta_go_dhcp'].GoDhcpServer()
        self.owner.dhcp = self.server
        self.server.binding, self.server.socket, self.server._socket_original = n.dhcp_binding, self.udp, self.udp
        for name, value in (('_stage', 'serving'), ('_service_called', True),
                ('_open_returned', True), ('_opening', False), ('_active', False),
                ('_close_called', False), ('_failure', None), ('_active_until', self.end),
                ('_active_until_original', self.end), ('_core', m['mta_go_dhcp'].wire.SingleClientServer())):
            setattr(self.server, name, value)
        self.server.model_context = lambda: self.events.append('inert_server_context')
        original = (self.canonical, self.end, n.dhcp_binding, self.server, n.dhcp_row, self.setup)
        n._dhcp_service_original = n._dhcp_service_issued_original = original
        n._dhcp_service_returned = True

        def old_dhcp_owner(actual, binding, server):
            self.events.append('inert_dhcp_owner')
            if binding is not n.dhcp_binding or server is not self.server:
                raise self.module.sources.GoSourceError('native_dhcp_owner_changed')
        n._dhcp_owner = types.MethodType(old_dhcp_owner, n)
        def old_full_ip(actual, original_ip, end):
            self.events.append('inert_full_ip')
            self.events.append(('inert_full_ip_end', end))
            actual._begin(end)
            if original_ip is not actual.ip_receipt:
                raise self.module.sources.GoSourceError('native_ip_not_original')
            return actual._ip_retained_current(original_ip)
        n.ip_current = types.MethodType(old_full_ip, n)
        n._controller = types.MethodType(lambda actual: self.events.append('inert_controller'), n)
        n.command_row = object()  # Only passed to the explicit original control seam.
        self.status_bytes = b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\nssid=DIRECT-model\n'
        def control_reply(actual, row, request):
            if row is not n.command_row or request != b'STATUS':
                raise AssertionError('HOST75 only modeled current AP STATUS')
            self.events.append('inert_status_reply')
            return self.status_bytes
        n._exchange = types.MethodType(control_reply, n)
        def old_durable(actual, phase, cleanup=False):
            self.events.append(('inert_durable', phase, cleanup))
            return self.store.current
        n._durable = types.MethodType(old_durable, n)

    def basis(self): return self.native.issue_send_basis(self.end)
    def cleanup(self):
        self.store.restore_attempted, self.store.restore_until = True, 61.0
        return self.native.close_send_inventory(self.store.restore_until)


class GoSendBasis75Test(unittest.TestCase):
    def test_go_credentials_and_owned_tcp(self):
        # Source read/imports happen before the syscall tripwires. Only actual
        # new definitions and original FD primitives execute under the model.
        forest = _SourceForest(_source_bytes())
        module = forest.native
        counts = {'valid_credentials': 0, 'credential_refusals': 0,
                  'native_fixtures': 0, 'refusal_checks': 0}
        completed = []
        with ExitStack() as stack:
            platform = _tripwires(stack)
            counts['valid_credentials'], counts['credential_refusals'] = _credential_cases(self, module)

            def fresh(name):
                counts['native_fixtures'] += 1
                return _Fixture(forest)

            def refused(action, code):
                with self.assertRaises(module.sources.GoSourceError) as caught:
                    action()
                self.assertEqual(code, caught.exception.code)
                counts['refusal_checks'] += 1
                return caught.exception

            with self.subTest(layer='native_pure_empty', case='empty_inventory'):
                f = fresh('empty_inventory')
                # New actual constructor defaults, not the synthetic serving
                # native's modeled IP/UDP inventory. Empty TCP is no restoration.
                empty = module.NativeGoResources(f.owner, _io=f.io)
                self.assertEqual([], empty.rows)
                self.assertEqual((), empty._history)
                self.assertEqual((), empty._send_tcp_rows_v75)
                self.assertIsNone(empty._scope)
                before = (list(f.events), f.entry.accounting._io_deadline,
                          list(f.io.factories), [list(raw.calls) for raw in f.io.raws])
                with mock.patch.object(_Clock, '__call__', side_effect=_forbidden) as clock_probe, \
                        mock.patch.object(f.io, 'tcp', side_effect=_forbidden) as factory_probe, \
                        mock.patch.object(f.io, 'fstat', side_effect=_forbidden) as fd_probe:
                    self.assertEqual((), empty.close_send_inventory(None))
                    self.assertEqual((), empty.close_send_inventory(object()))
                    for probe in (clock_probe, factory_probe, fd_probe):
                        self.assertEqual(0, probe.call_count)
                self.assertIsNone(empty._scope)
                self.assertIsNone(empty.last)
                self.assertIs(empty._scope_cleanup, False)
                self.assertIs(empty._send_close_attempted_v75, False)
                self.assertEqual(before, (list(f.events), f.entry.accounting._io_deadline,
                    list(f.io.factories), [list(raw.calls) for raw in f.io.raws]))
                completed.append('empty_inventory')

            with self.subTest(layer='native_narrowing', case='narrow_cap'):
                f = fresh('narrow_cap')
                n, narrow = f.native, 17.0
                basis = n.issue_send_basis(narrow)
                self.assertIs(basis.end, narrow)
                self.assertIs(n._scope, narrow)
                self.assertIs(f.owner.service_until, f.end)
                self.assertIs(n._dhcp_service_original[1], f.end)
                refused(lambda: n.open_send_listener(basis, 18.0),
                        'native_send_basis_not_original')
                self.assertIs(n._send_listener_attempted, False)
                self.assertEqual([], f.io.factories)
                listener = n.open_send_listener(basis, narrow)
                self.assertIs(listener.end, narrow)
                self.assertIs(n._scope, narrow)
                ends = [event[1] for event in f.events if type(event) is tuple and
                        event[0] == 'inert_full_ip_end']
                self.assertEqual(2, len(ends))
                for end in ends: self.assertIs(end, narrow)
                self.assertIs(f.entry.accounting._io_deadline, narrow)
                self.assertEqual(((True, True),), f.cleanup())
                self.assertEqual(1, listener.raw.close_calls)
                self.assertIs(f.owner.service_until, f.end)
                self.assertEqual(301.0, n.until)
                completed.append('narrow_cap')

            with self.subTest(layer='native_tcp', case='original_basis_and_listener'):
                f = fresh('original_basis_and_listener')
                n = f.native
                basis = f.basis()
                self.assertIs(type(basis), module.GoSendBasis)
                self.assertIs(basis, n._send_basis_original)
                self.assertIs(basis, n._send_basis_issued_original)
                self.assertIs(basis.end, f.end)
                self.assertIs(basis.canonical, f.canonical)
                self.assertIs(basis.history, f.store._canonical_history)
                self.assertIs(basis.service_tuple, n._dhcp_service_original)
                self.assertIs(basis.ip, n.ip_receipt)
                self.assertIs(basis.ack, n._ip_ack_original)
                self.assertIs(basis.origin, f.origin)
                self.assertEqual('DIRECT-model', basis.ssid)
                self.assertEqual(b'DIRECT-model', basis.ssid_bytes)
                self.assertEqual('12'*32, basis.psk)
                self.assertEqual(bytes((2, 17, 34, 51, 68, 85)), basis.go_dev_addr)
                self.assertIs(basis.dhcp_raw, f.udp)
                self.assertIs(basis.current_status_raw, f.status_bytes)
                self.assertIs(n._send_basis_returned, True)
                self.assertEqual(1, f.events.count('inert_full_ip'))
                self.assertEqual(1, f.events.count('inert_status_reply'))
                with self.assertRaises(AttributeError): basis.end = 100.0
                self.assertNotIn('12'*32, repr(basis))
                refused(f.basis, 'native_send_basis_already_attempted')
                self.assertEqual(1, f.events.count('inert_full_ip'))

                f.io.fileno_retained[:] = []  # Ignore constructor-only modeled IP/UDP adoption.
                listener = n.open_send_listener(basis, f.end)
                self.assertIs(type(listener), module.GoSendListener)
                self.assertIs(listener, n._send_listener_original)
                self.assertIs(listener.basis, basis)
                self.assertIs(listener.end, f.end)
                self.assertIs(n._send_listener_returned, True)
                row, raw = listener.row, listener.raw
                self.assertIs(row, n._send_tcp_rows_v75[0])
                self.assertIs(row, n._send_tcp_history_v75[0])
                self.assertIs(row.value, raw)
                self.assertEqual('tcp', row.kind)
                self.assertIs(row._tcp_factory_called_v75, True)
                self.assertIs(row._tcp_bind_called_v75, True)
                self.assertIs(row.bound, False)  # TCP must never take the UNIX unlink branch.
                self.assertIs(row.unlink_called, False)
                self.assertIs(row.returned, True)
                self.assertIs(row.unknown, False)
                self.assertEqual(('192.168.49.1', 32123), listener.endpoint)
                self.assertEqual(32123, listener.port)
                self.assertIs(listener.metadata, row.metadata)
                self.assertEqual([('bind', ('192.168.49.1', 0))],
                                 [c for c in raw.calls if c[0] == 'bind'])
                self.assertEqual(b'mta01234567\0', raw.options[(socket.SOL_SOCKET, 25)])
                self.assertEqual(struct.pack('ii', 0, 0), raw.options[(socket.SOL_SOCKET, socket.SO_LINGER)])
                self.assertIs(raw.inheritable, False)
                self.assertIs(raw.blocking, False)
                self.assertEqual(1, len(f.io.factories))
                self.assertIs(f.io.factories[0][-1], row)  # Registered before actual modeled factory.
                self.assertTrue(f.io.fileno_retained)
                self.assertTrue(all(f.io.fileno_retained))  # Raw retained before every fileno observation.
                self.assertEqual(2, f.events.count('inert_full_ip'))
                refused(lambda: n.open_send_listener(basis, f.end), 'native_send_listener_already_attempted')
                self.assertEqual(1, len(f.io.factories))
                with self.assertRaises(AttributeError): listener.port = 1
                self.assertEqual(((True, True),), f.cleanup())
                self.assertEqual(1, raw.close_calls)
                self.assertIs(row.closed, True)
                self.assertIs(row.unknown, False)
                self.assertEqual(((True, True),), n.close_send_inventory(f.store.restore_until))
                self.assertEqual(1, raw.close_calls)  # Read-only known closure, no second close.
                self.assertEqual(301.0, n.until)
                self.assertIs(f.owner.service_until, f.end)
                completed.append('original_basis_and_listener')

            # Each denial has an independent synthetic serving boundary.
            for name in ('wrong_worker', 'service_expansion', 'copied_basis',
                         'canonical_replaced', 'service_replaced', 'expired', 'ssid_mismatch'):
                with self.subTest(layer='original_boundary_refusal', case=name):
                    f = fresh(name)
                    n = f.native
                    if name == 'wrong_worker':
                        n.worker = object()
                        refused(f.basis, 'native_owner_changed')
                    elif name == 'service_expansion':
                        refused(lambda: n.issue_send_basis(22.0), 'native_send_service_changed')
                    elif name == 'ssid_mismatch':
                        f.status_bytes = b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\nssid=OTHER\n'
                        refused(f.basis, 'native_send_ssid_changed')
                        self.assertIs(n._send_basis_attempted, True)
                        self.assertIs(n._send_basis_returned, False)
                        self.assertIsNone(n._send_basis_original)
                        refused(f.basis, 'native_send_basis_already_attempted')
                    else:
                        basis = f.basis()
                        if name == 'copied_basis':
                            copied = module.GoSendBasis(n, f.end, n._send_credentials_original_v75,
                                                        n._send_status_raw_v75)
                            refused(lambda: n.open_send_listener(copied, f.end), 'native_send_basis_not_original')
                        elif name == 'canonical_replaced':
                            replacement = forest.modules['mta_go_bootstrap_store'].GoCanonical()
                            replacement.issuer, replacement.record = f.canonical.issuer, f.canonical.record
                            f.store.current = replacement
                            refused(lambda: n.open_send_listener(basis, f.end), 'native_send_service_changed')
                        elif name == 'service_replaced':
                            n._dhcp_service_original = tuple(list(n._dhcp_service_original))
                            self.assertIsNot(n._dhcp_service_original, n._dhcp_service_issued_original)
                            refused(lambda: n.open_send_listener(basis, f.end), 'native_send_service_changed')
                        elif name == 'expired':
                            f.clock.value = f.end
                            refused(lambda: n.open_send_listener(basis, f.end), 'deadline')
                    self.assertEqual([], f.io.factories)
                    self.assertEqual((), n._send_tcp_rows_v75)
                    self.assertEqual(301.0, n.until)
                    self.assertIs(f.owner.service_until, f.end)
                    completed.append(name)

            for name in ('factory', 'fileno', 'late_bind', 'close_unknown'):
                with self.subTest(layer='native_resource_refusal', case=name):
                    f = fresh(name)
                    n, basis = f.native, f.basis()
                    f.io.fault = name if name != 'close_unknown' else None
                    if name == 'close_unknown':
                        listener = n.open_send_listener(basis, f.end)
                        row, raw = listener.row, listener.raw
                        raw.fault = name
                        with self.assertRaises(OSError) as caught: f.cleanup()
                        self.assertEqual(errno.EIO, caught.exception.errno)
                        self.assertIs(row.close_failure, caught.exception)
                        self.assertIs(row.attempted, True)
                        self.assertIs(row.closed, False)
                        self.assertEqual(1, raw.close_calls)
                        # All five actual new cleanup gates reject before their
                        # preexisting durable/IO path, even though raw's model
                        # physically closed. Unknown return is not a certificate.
                        before = list(f.events)
                        for method in (n.close_dhcp, n.prepare_ip_cleanup, n.restore_ip,
                                       n.prepare_cleanup, n.delete_interface):
                            refused(lambda method=method: method(f.store.restore_until),
                                    'native_send_inventory_pending')
                        self.assertEqual(before, f.events)
                        refused(lambda: n.close_send_inventory(f.store.restore_until),
                                'native_send_inventory_pending')
                        self.assertEqual(1, raw.close_calls)
                    elif name == 'late_bind':
                        refused(lambda: n.open_send_listener(basis, f.end), 'deadline')
                        row = n._send_tcp_rows_v75[0]
                        raw = row.value
                        self.assertIs(row.returned, True)
                        self.assertIs(row.unknown, False)
                        self.assertIs(row._tcp_bind_called_v75, True)
                        self.assertIs(n._send_listener_returned, False)
                        self.assertIsNone(n._send_listener_original)
                        self.assertEqual(f.end, f.clock.value)
                        self.assertEqual(((True, True),), f.cleanup())
                        self.assertEqual(1, raw.close_calls)
                        self.assertIs(row.bound, False)
                    else:
                        with self.assertRaises(OSError) as caught:
                            n.open_send_listener(basis, f.end)
                        self.assertEqual(errno.EMFILE if name == 'factory' else errno.EIO,
                                         caught.exception.errno)
                        row = n._send_tcp_rows_v75[0]
                        self.assertIs(row.failure, caught.exception)
                        self.assertIs(n._send_listener_attempted, True)
                        self.assertIs(n._send_listener_returned, False)
                        self.assertIsNone(n._send_listener_original)
                        self.assertIs(f.io.factories[-1][-1], row)
                        if name == 'factory':
                            self.assertIs(row.returned, False)
                            self.assertIsNone(row.value)
                            self.assertIs(row.attempted, True)
                            self.assertIs(row.closed, True)  # Known no-return, NOT a closed FD proof.
                            self.assertIs(row.unknown, False)
                            self.assertEqual(((True, True),), f.cleanup())
                        else:
                            self.assertIs(row.returned, True)
                            self.assertIs(row.value, f.io.raws[-1])
                            self.assertIsNone(row.fd)
                            self.assertIsNone(row.metadata)
                            self.assertIs(row.unknown, True)
                            self.assertEqual(0, row.value.close_calls)
                            refused(f.cleanup, 'native_send_inventory_pending')
                            self.assertEqual(0, row.value.close_calls)
                    refused(lambda: n.open_send_listener(basis, f.end),
                            'native_send_listener_already_attempted')
                    self.assertEqual(1, len(f.io.factories))
                    self.assertEqual(301.0, n.until)
                    self.assertIs(f.owner.service_until, f.end)
                    completed.append(name)

            self.assertEqual(4, counts['valid_credentials'])
            self.assertEqual(16, counts['credential_refusals'])
            self.assertEqual(14, counts['native_fixtures'])
            self.assertEqual(14, len(completed))
            self.assertEqual(23, counts['refusal_checks'])
            for guard in platform: self.assertEqual(0, guard.call_count)
        print(MARKER, end='')


if __name__ == '__main__':
    unittest.main()
