"""Unexecuted R4 SOURCE: Native76 transport with private stall attribution.

Future ROOT-only WSL root execution; no network/interface configuration, radio,
GATT, device or phone operation is performed. Only a phone-protocol fixture has
a thread. The actual Native76 owner and SenderPump stay on the original worker
with its RLock held, using real lo SO_BINDTODEVICE, TCP, SSL, fstat and EBADF.

The fixed complete source definitions are loaded in a private import domain,
not by importing any previous TestCase. Loader authentication, GO ownership,
durable journal, IP installation, DHCP issuance/ACK transmission and credentials
are explicit antecedent fixtures, not successful production producers. In
particular lo/127.0.0.x cannot pass the old mta-interface/RFC1918 constructors;
exact-class __new__ antecedents below do not grant those permissions. New76
STA/ACK matching, prelisten, owner issuance, accept, wrap/detach and close are
not replaced. New76 kernel transport is the only Native layer under test.

PreparedSend and the protocol client are actual dependencies, not replayed old
test methods. Certificates/keys, peer fields, paths and exception text remain
private. Successful stdout is exactly one fixed nonsecret marker. SOURCE only:
the author must not execute/import/AST-parse this file, WSL, a test or a device.
"""
import builtins
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time
import traceback
import types
import unittest
import warnings
import zipfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    'host/go_send_transport_v76_definition_manifest.json',
    '045d28f552e572182b7d2653863eccb6ced9b26a7f3aee093fae69ea0fba9eac', 4556)
NATIVE_SOURCE = (
    'candidate/go-send-transport-v76/runtime/mta_go_native.py',
    'ee46d8313fe31cbc5a0d16d0d14aff7ce2b3fb507f3cdac572e59bc5f16dfa9f', 200317)
RUNTIME_SOURCES = (
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 17958),
    ('mta_storage', 'runtime/mta_storage.py',
     '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6', 14335),
    ('mta_files', 'runtime/mta_files.py',
     'c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae', 10267),
    ('mta_transport', 'runtime/mta_transport.py',
     '29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72', 31883),
    ('mta_send_preparation', 'runtime/mta_send_preparation.py',
     '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814', 28532),
    ('mta_sender_pump', 'runtime/mta_sender_pump.py',
     '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c', 33455),
)
OPENSSL = '/usr/bin/openssl'
MARKER = ('HOST76_GO_SEND_TRANSPORT new_methods=1 old_methods=0 '
          'linux_kernel=true loopback_tls=true ancestors_model=true '
          'device=false phone=false\n')


def _bytes(reference):
    if type(reference) is not tuple or len(reference) != 3:
        raise AssertionError('HOST76 final source pin unavailable')
    raw = (ROOT / reference[0]).read_bytes()
    if len(raw) != reference[2] or hashlib.sha256(raw).hexdigest() != reference[1]:
        raise AssertionError('HOST76 fixed source changed')
    return raw


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST76 ancestor/RF/platform operation forbidden')


class _Definitions(object):
    """Whole definitions only, not Loader authentication or a GO20 admission."""
    def __init__(self):
        data = json.loads(_bytes(MANIFEST).decode('utf-8'))
        rows = data['sources']
        if type(rows) is not list or len(rows) != 20:
            raise AssertionError('HOST76 fixed GO20 source inventory changed')
        native = [r for r in rows if r['module'] == 'mta_go_native']
        if len(native) != 1 or (native[0]['path'], native[0]['sha256'], native[0]['bytes']) != NATIVE_SOURCE:
            raise AssertionError('HOST76 Native source binding changed')
        references = [(r['module'], (r['path'], r['sha256'], r['bytes'])) for r in rows]
        references += [(name, (path, sha, size)) for name, path, sha, size in RUNTIME_SOURCES]
        names = [name for name, reference in references]
        if len(set(names)) != len(names):
            raise AssertionError('HOST76 private definition names duplicated')
        self.modules = {name: types.ModuleType(name) for name in names}
        original_import = builtins.__import__

        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if not level and name in self.modules:
                return self.modules[name]
            if level or name.startswith(('mta_', 'p011_')):
                raise AssertionError('HOST76 undeclared private dependency')
            return original_import(name, globals, locals, fromlist, level)

        for name, reference in references:
            module = self.modules[name]
            module.__file__ = str(ROOT / reference[0])
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            exec(compile(_bytes(reference), name, 'exec'), module.__dict__)
        self.native = self.modules['mta_go_native']
        self.pump = self.modules['mta_sender_pump']
        self.preparation = self.modules['mta_send_preparation']
        self.files = self.modules['mta_files']
        self.transport = self.modules['mta_transport']
        self.protocol = self.modules['mta_protocol']


class _KernelIo(object):
    """No syscall simulation: TCP factory and every fstat are actual Linux."""
    def __init__(self):
        self.native = None
        self.created = []
        self.pre_factory_inventory = []
        self.stats = []

    def tcp(self):
        self.pre_factory_inventory.append(tuple(self.native.rows))
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.created.append(raw)
        return raw

    def fstat(self, fd):
        event = {'fd': fd, 'metadata': None, 'errno': None}
        self.stats.append(event)
        try:
            value = os.fstat(fd)
            event['metadata'] = _metadata(value)
            return value
        except OSError as error:
            event['errno'] = error.errno
            raise

    validate = open = read = close = stat = readlink = _forbidden


def _ebadf(test, fd):
    with test.assertRaises(OSError) as caught:
        os.fstat(fd)
    test.assertIs(type(caught.exception.errno), int)
    test.assertEqual(errno.EBADF, caught.exception.errno)


def _metadata(value):
    return tuple(getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev'))


class _PhonePeer(object):
    """Simulated phone identity; actual two TLS connections and protocol IO."""
    def __init__(self, definitions, port, task, end):
        self.definitions, self.port, self.task, self.end = definitions, port, task, end
        self.sockets, self.errors, self.events, self.certificates = [], [], [], []
        self.archive, self.ack, self.thread = None, None, None
        self.done = threading.Event()
        self.phase, self.phase_times = 'new', []

    def _phase(self, phase):
        self.phase = phase
        self.phase_times.append((phase, time.monotonic()))  # Diagnostic, no cap issuance.

    def _connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # 127/8 is already loopback. No address, route or interface is changed.
        self._phase('tcp_connect')
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3.0,
                                       source_address=('127.0.0.2', 0))
        self.sockets.append(raw)
        self._phase('tls_handshake')
        wrapped = context.wrap_socket(raw, server_hostname='127.0.0.1')
        self._phase('tls_connected')
        self.sockets.append(wrapped)
        self.certificates.append(hashlib.sha256(wrapped.getpeercert(binary_form=True)).digest())
        return self.definitions.transport.Stream(wrapped, deadline=self.end)

    def run(self):
        transport, protocol = self.definitions.transport, self.definitions.protocol
        try:
            stream = self._connect()
            self._phase('websocket_upgrade')
            ws = transport.websocket_client(stream, '127.0.0.1', self.port)
            self._phase('version_receive')
            version = ws.receive()
            if (version.msg_type, version.name, version.id) != ('action', 'versionNegotiation', 0):
                raise AssertionError('HOST76 version action changed')
            self._phase('version_ack_send')
            ws.send(version.make_ack({'version': 1, 'threadLimit': 1}))
            self._phase('request_receive')
            request = ws.receive()
            if (request.msg_type, request.name, request.id) != ('action', 'sendRequest', 1) or \
                    request.payload['taskId'] != self.task:
                raise AssertionError('HOST76 original send request changed')
            self._phase('request_ack_send')
            ws.send(request.make_ack())
            self.events.append('accepted')
            download = self._connect()
            self.events.append('download_while_ws_open')
            download.send(('GET /download?taskId=' + self.task +
                ' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode('ascii'))
            self._phase('download_headers')
            first, headers = transport.read_headers(download)
            if not first.startswith(b'HTTP/1.1 200 '):
                raise AssertionError('HOST76 download HTTP status changed')
            target = io.BytesIO()
            self._phase('download_body')
            transport.download_body(download, headers, target)
            self.archive = target.getvalue()
            self.events.append('download_complete')
            status = protocol.WsMessage('action', 2, 'status',
                {'taskId': self.task, 'id': self.task, 'type': 1, 'reason': 'HOST fixture'})
            self._phase('completion_send')
            ws.send(status)
            self._phase('completion_ack_receive')
            self.ack = ws.receive()
            if (self.ack.msg_type, self.ack.name, self.ack.id) != ('ack', 'status', 2):
                raise AssertionError('HOST76 terminal ACK changed')
            self.events.append('ack_received')
            self._phase('completed')
        except BaseException as error:
            self.errors.append(error)
        finally:
            for raw in reversed(self.sockets):
                raw.close()
            self.done.set()

    def start(self):
        self.thread = threading.Thread(target=self.run, name='HOST76_phone_protocol_fixture')
        self.thread.start()

    def join(self):
        self.thread.join(5.0)
        return not self.thread.is_alive()


def _capture_cleanup(failures, role, callback):
    """Retain the same exception/traceback; never turn cleanup uncertainty PASS."""
    try:
        callback()
    except BaseException as error:
        failures.append((role, error, error.__traceback__))


class _PreparedInput(object):
    def __init__(self, definitions, directory, until):
        # Retain this fixture before __init__; partial prepare must remain
        # reachable even when its original archive/selection export failed.
        self.directory = directory
        self.selection = self.prepared = self.archive = None
        self.private_directory = self.directory_metadata = None
        self.cleanup_failures = ()
        self.cleanup_until = until + 4.0  # Original fixed BEFORE preparation IO.
        user = os.path.join(directory, 'user')
        os.makedirs(os.path.join(user, 'Text'))
        self.data = os.urandom(256 * 1024)
        with open(os.path.join(user, 'Text', 'kernel-transfer.bin'), 'wb') as output:
            output.write(self.data)
        registry = definitions.files.FileRegistry(user)
        self.selection = registry.open_selection([row['id'] for row in registry.list_files()])
        self.member = '0/' + self.selection.entries[0]['name']
        self.prepared = definitions.preparation.PreparedSend(self.selection, OPENSSL,
            'host76-kernel-task', 'host76sender', until, directory)
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message=r'ssl\.PROTOCOL_TLSv1_2 is deprecated',
                                    category=DeprecationWarning)
            if self.prepared.prepare() is not self.prepared:
                raise AssertionError('HOST76 original preparation changed')
        self.archive = self.prepared.archive_handle
        self.archive_bytes = self.archive.read()
        self.archive.seek(0)
        self.private_directory = self.prepared._directory
        self.directory_metadata = os.lstat(self.private_directory)

    def close(self, test):
        failures, archive_fd, selection_fds = [], [], []
        # Observation cannot prevent the actual original close attempt.
        def observe_prepared():
            if self.archive is not None:
                archive_fd.append(self.archive.fileno())
            if self.private_directory is not None:
                now = os.lstat(self.private_directory)
                test.assertEqual((self.directory_metadata.st_dev, self.directory_metadata.st_ino),
                                 (now.st_dev, now.st_ino))
        _capture_cleanup(failures, 'prepared_before_close', observe_prepared)

        def close_prepared():
            if self.prepared is None:
                return  # Pure/early ctor retained no PreparedSend resources.
            test.assertIs(self.prepared.close(self.cleanup_until), True)
            for fd in archive_fd:
                _ebadf(test, fd)  # Immediately before any new FD can reuse it.
            if self.private_directory is not None:
                test.assertFalse(os.path.lexists(self.private_directory))
            test.assertIs(self.prepared.status()['resource_pending'], False)
        _capture_cleanup(failures, 'prepared_close', close_prepared)

        def observe_selection():
            if self.selection is None:
                return
            for entry in self.selection.entries:
                selection_fds.append(entry['handle'].fileno())
                test.assertFalse(entry['handle'].closed)
                entry['handle'].seek(0)
                test.assertEqual(self.data, entry['handle'].read())
        _capture_cleanup(failures, 'selection_before_close', observe_selection)

        def close_selection():
            if self.selection is None:
                return
            self.selection.close()
            for fd in selection_fds:
                _ebadf(test, fd)
            test.assertIs(self.selection.lifecycle_status()['closure_verified'], True)
        _capture_cleanup(failures, 'selection_close', close_selection)
        self.cleanup_failures = tuple(failures)
        if failures:
            unused, error, original_traceback = failures[0]
            raise error.with_traceback(original_traceback)


class _NativeAntecedents(object):
    """Explicit old-layer premises; never production GO/IP/DHCP permission.

    Actual Source classes are used for identity checks, but the GoStore,
    Bootstrap, entry, IP facts, DHCP core and prior basis are inert antecedents.
    They deliberately bypass constructors which prohibit loopback as a GO.
    No authenticate/reserve/CAS/CREATE/address add/DHCP packet occurs. The new
    Native methods are untouched; actual GoDhcpServer._context and old retained
    IP/FD plus new TCP readback still execute. Old75 serving-UDP readback is
    an explicit ancestor seam below: actual lo ephemeral UDP identity/options,
    NOT ANY:67/DORA/ACK evidence. The unused IP-row netlink socket sends no
    request. The actual UDP socket sends no DHCP packet.
    """
    def __init__(self, definitions, end, cleanup_end):
        m, module = definitions.modules, definitions.native
        self.definitions, self.module = definitions, module
        self.native = self.store = self.owner = None
        self.mutex_held = False
        self.cleanup_failures = ()
        self.worker, self.mutex, self.clock = threading.current_thread(), threading.RLock(), time.monotonic
        self.end, self.until, self.cleanup_end = end, end + 10.0, cleanup_end
        self.setup = end - 5.0
        self.events, self.control_queries = [], []
        self.io = _KernelIo()
        self.ip_socket = self.udp = None
        self.mutex.acquire()  # Original worker retains the same lock throughout.
        self.mutex_held = True
        self.owner = object.__new__(m['mta_go_bootstrap'].GoBootstrap)
        self.store = object.__new__(m['mta_go_bootstrap_store'].GoBootstrapStore)
        self.deployment = object.__new__(m['mta_go_deployment'].LoadedGoDeployment)
        object.__setattr__(self.deployment, 'modules', m)
        self.entry = types.SimpleNamespace(clock=self.clock, until=self.until,
            accounting=types.SimpleNamespace(_io_deadline=None))
        for name, value in (('until', self.until), ('worker', self.worker),
                ('mutex', self.mutex), ('clock', self.clock), ('owner', self.owner),
                ('issuer', object()), ('restore_attempted', False), ('restore_until', None),
                ('publication_unknown', False), ('failure', None)):
            setattr(self.store, name, value)
        for name, value in (('store', self.store), ('deployment', self.deployment),
                ('entry', self.entry), ('stop_requested', False), ('restore_attempted', False),
                ('service_until', self.end), ('_service_until_original', self.end),
                ('setup_until', self.setup), ('_setup_until_original', self.setup),
                ('controller', object())):
            setattr(self.owner, name, value)
        self.native = module.NativeGoResources(self.owner, _io=self.io)
        self.owner.native = self.io.native = self.native
        n = self.native

        def old_owner(actual):
            # This ancestor seam does not infer a live single-threaded GO F.
            # It still forbids moving actual new transport calls to the phone
            # thread, substituting old parent pointers or changing inventory.
            self.events.append('modeled_ancestor_owner')
            if threading.current_thread() is not self.worker or actual.worker is not self.worker or \
                    getattr(self.mutex, '_is_owned')() is not True or \
                    any(a is not b for a, b in zip((self.owner, self.store, self.deployment,
                        self.until, self.worker, self.mutex, self.clock, self.entry, self.io), actual._originals)) or \
                    actual.rows is not actual._rows_original or type(actual._history) is not tuple or \
                    len(actual.rows) != len(actual._history) or \
                    any(a is not b for a, b in zip(actual.rows, actual._history)):
                raise module.sources.GoSourceError('native_owner_changed')
        n._owner = types.MethodType(old_owner, n)
        # Only this preexisting cancellation boundary is inert. Real monotonic
        # _now/_begin/_check and every original Native IO postcheck are kept.
        m['mta_go_bootstrap'].GoBootstrap._cancelled = lambda owner, until: owner.stop_requested
        n._begin(self.end)

        self.origin = m['mta_p2p_client_init'].Origin(0, 8, socket.if_nametoindex('lo'), 'lo', 9)
        ip = m['mta_ip']
        # Bypassed RFC1918/mta ancestry is declared, not silently relaxed in
        # production. The pure exact class keeps actual source_key semantics.
        spec = tuple.__new__(ip.AddressSpec, (self.origin.ifindex, 0x7f000001, 24))
        address = ip.AddressRecord(self.origin.ifindex, 0x7f000001, 0x7f000001,
            24, 0, 0, b'lo\0', None, (0xffffffff, 0xffffffff, 0, 0))

        def ip_facts(phase):
            value = object.__new__(m['mta_go_bootstrap_store'].GoIpFacts)
            for name, item in (('phase', phase), ('origin', self.origin), ('spec', spec),
                               ('request', ()), ('address', address)):
                object.__setattr__(value, name, item)
            return value
        facts, confirmed = ip_facts('receipt_recorded'), ip_facts('confirmed')
        self.ip_intent = module.GoIpObservation(n, facts)
        n.ip_intent = self.ip_intent
        n.ip_receipt = module.GoIpObservation(n, facts)
        n.observations.extend((self.ip_intent, n.ip_receipt))
        n.ip_ack = n._ip_ack_original = ip.AckResult(0, ip.RTM_NEWADDR)
        n._ip_create_called = True  # Modeled historic ACK premise, no NEWADDR IO.
        n._ip_original = types.MethodType(lambda actual: self.ip_intent, n)
        self.group = module.GoGroupObservation(n, b'HOST76 synthetic prior GO event\n',
            b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\n', 2412, self.origin)
        n.group, n.owned = self.group, self.origin
        self.canonical = m['mta_go_bootstrap_store'].GoCanonical(self.store.issuer,
            types.SimpleNamespace(phase='dhcp_listening', ip=confirmed,
                                  dhcp=types.SimpleNamespace(phase='listening')), b'', ())
        self.store.current, self.store._canonical_history = self.canonical, (self.canonical,)
        n._dhcp_setup_c2, n._dhcp_setup_h2 = self.canonical, self.store._canonical_history
        n._dhcp_setup_until_original = self.setup

        n.ip_row = n._record('netlink', True)
        self.ip_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        self.ip_socket.set_inheritable(False)
        n._adopt(n.ip_row, self.ip_socket, self.ip_socket.fileno())
        n.dhcp_row = n._dhcp_row_original = n._record('udp', True)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.udp.set_inheritable(False)
        self.udp.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp.setsockopt(socket.IPPROTO_IP, 8, 1)
        self.udp.setblocking(False)
        # No use of the HOST's occupied service port and no namespace/network
        # changes: this old DHCP premise is a real unused lo ephemeral socket.
        self.udp.bind(('127.0.0.1', 0))
        self.udp_endpoint_original = self.udp.getsockname()
        n._adopt(n.dhcp_row, self.udp, self.udp.fileno())
        self.udp_fd_original, self.udp_metadata_original = n.dhcp_row.fd, n.dhcp_row.metadata
        n.dhcp_binding = module.GoDhcpBinding(n, n.ip_receipt)
        self.server = m['mta_go_dhcp'].GoDhcpServer(n.dhcp_binding)  # Actual pure ctor.
        self.owner.dhcp = self.server
        self.server.socket = self.server._socket_original = self.udp
        wire = m['mta_dhcp']
        self.core = object.__new__(wire.SingleClientServer)
        self.station = bytes((2, 16, 32, 48, 64, 80))
        self.selected = bytes((2, 96, 112, 128, 144, 160))
        self.selected_text = '02:60:70:80:90:a0'
        for name, value in (('server', struct.pack('!I', n.dhcp_binding.server_ip)),
                ('client', struct.pack('!I', n.dhcp_binding.client_ip)),
                ('mask', struct.pack('!I', n.dhcp_binding.subnet_mask)), ('deadline', self.end),
                ('expected_mac', self.station), ('key', (self.station, None)),
                ('offered_xid', 1), ('bound', True), ('declined', False)):
            setattr(self.core, name, value)
        self.allocation = {'client_ip': n.dhcp_binding.client_ip, 'mac': self.station,
            'usable_until': self.end, 'ack_transmitted': True, 'phone_configured': False}
        for name, value in (('_stage', 'serving'), ('_service_called', True),
                ('_open_called', True), ('_open_returned', True), ('_opening', False),
                ('_active', False), ('_close_called', False), ('_failure', None),
                ('_active_until', self.end), ('_active_until_original', self.end),
                ('_core', self.core), ('_allocation', self.allocation)):
            setattr(self.server, name, value)
        original = (self.canonical, self.end, n.dhcp_binding, self.server, n.dhcp_row, self.setup)
        n._dhcp_service_original = n._dhcp_service_issued_original = original
        n._dhcp_service_returned = True

        def old_dhcp_owner(actual, binding, server):
            self.events.append('modeled_dhcp_ancestor')
            if binding is not n.dhcp_binding or server is not self.server:
                raise module.sources.GoSourceError('native_dhcp_owner_changed')
        n._dhcp_owner = types.MethodType(old_dhcp_owner, n)

        def modeled_ephemeral_udp_current(actual):
            # Only the preexisting75 DHCP ancestry is modeled. No new76 peer,
            # listener/accept/wrap/detach/close producer is replaced.
            row, raw = actual.dhcp_row, self.udp
            actual._fd_current(row)
            if row is not actual._dhcp_row_original or row.value is not raw or \
                    raw is not self.server.socket or raw is not self.server._socket_original or \
                    row.fd != self.udp_fd_original or row.metadata is not self.udp_metadata_original:
                raise module.sources.GoSourceError('native_send_udp_changed')
            actual._check(); endpoint = raw.getsockname(); actual._check()
            if type(self.udp_endpoint_original) is not tuple or len(self.udp_endpoint_original) != 2 or \
                    self.udp_endpoint_original[0] != '127.0.0.1' or \
                    type(self.udp_endpoint_original[1]) is not int or \
                    not 1 <= self.udp_endpoint_original[1] <= 65535 or endpoint != self.udp_endpoint_original:
                raise module.sources.GoSourceError('native_send_udp_changed')
            actual._check(); device = raw.getsockopt(socket.SOL_SOCKET, 25, 16); actual._check()
            if type(device) is not bytes or device != b'lo\0':
                raise module.sources.GoSourceError('native_send_udp_changed')
            for level, option, expected in ((socket.SOL_SOCKET, socket.SO_TYPE, socket.SOCK_DGRAM),
                    (socket.SOL_SOCKET, socket.SO_REUSEADDR, 0), (socket.SOL_SOCKET, 15, 0),
                    (socket.SOL_SOCKET, socket.SO_BROADCAST, 1), (socket.IPPROTO_IP, 8, 1)):
                actual._check(); value = raw.getsockopt(level, option); actual._check()
                if type(value) is not int or value != expected:
                    raise module.sources.GoSourceError('native_send_udp_changed')
            actual._check(); inheritable = raw.get_inheritable(); actual._check()
            if inheritable is not False or raw.getblocking() is not False:
                raise module.sources.GoSourceError('native_send_udp_changed')
            actual._fd_current(row)
            self.events.append('modeled_ephemeral_udp_readback')
            return row
        n._send_udp_current_v75 = types.MethodType(modeled_ephemeral_udp_current, n)
        def old_full_ip(actual, original_ip, until):
            self.events.append(('modeled_full_ip_boundary', until))
            actual._begin(until)
            if original_ip is not actual.ip_receipt:
                raise module.sources.GoSourceError('native_ip_not_original')
            return actual._ip_retained_current(original_ip)
        n.ip_current = types.MethodType(old_full_ip, n)
        n._controller = types.MethodType(lambda actual: self.events.append('modeled_controller'), n)
        n._interfaces = types.MethodType(lambda actual: ((self.origin, 2412, b''),), n)
        n.command_row = object()  # Only consumed by the modeled control read.
        self.station_raw = (b'02:10:20:30:40:50\n'
            b'flags=[AUTH][ASSOC][AUTHORIZED]\naid=1\ncapability=0x1\n'
            b'listen_interval=1\nsupported_rates=82 84 8b 96\ntimeout_next=NULLFUNC POLL\n'
            b'p2p_device_addr=02:60:70:80:90:a0\n')
        def old_control_reply(actual, row, request):
            if row is not n.command_row:
                raise AssertionError('HOST76 foreign control row')
            self.control_queries.append(request)
            if request in (b'STA-FIRST', b'STA 02:10:20:30:40:50'):
                return self.station_raw
            if request == b'STA-NEXT 02:10:20:30:40:50':
                return b''
            raise AssertionError('HOST76 unexpected ancestor WPA query')
        n._exchange = types.MethodType(old_control_reply, n)
        # Prior basis is MODEL DATA, not issue_send_basis success. New76 rejects
        # foreign/mutated identities against the actual retained same originals.
        credentials = module._GoCredentialsV75('DIRECT-host76', b'DIRECT-host76',
                                               '12' * 32, bytes((2, 1, 2, 3, 4, 5)))
        status_raw = b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\nssid=DIRECT-host76\n'
        n._send_status_raw_v75 = status_raw
        n._send_credentials_original_v75 = credentials
        n._send_basis_end_original = self.end
        self.basis = module.GoSendBasis(n, self.end, credentials, status_raw)
        n._send_basis_original = n._send_basis_issued_original = self.basis
        n._send_basis_attempted = n._send_basis_returned = True

    def close_antecedent_sockets(self, test):
        # Actual original FD once-close is not GO/IP/DHCP restoration. Each
        # row is independent: an unadopted UDP row must not skip known IP close.
        failures = []
        if self.native is not None:
            self.store.restore_attempted, self.store.restore_until = True, self.cleanup_end
            for role in ('dhcp_row', 'ip_row'):
                row = getattr(self.native, role)
                if row is None:
                    continue
                def close_row(row=row):
                    fd = row.fd
                    self.native._close(row, self.cleanup_end)
                    test.assertIs(row.attempted, True)
                    test.assertIs(row.closed, True)
                    test.assertIs(row.unknown, False)
                    _ebadf(test, fd)
                _capture_cleanup(failures, role, close_row)
        self.cleanup_failures = tuple(failures)
        if failures:
            unused, error, original_traceback = failures[0]
            raise error.with_traceback(original_traceback)

    def release_fixture_lock(self):
        if self.mutex_held:
            self.mutex.release()
            self.mutex_held = False


def _masked_frames(wire):
    unused, separator, data = wire.partition(b'\r\n\r\n')
    if separator != b'\r\n\r\n':
        raise AssertionError('HOST76 client upgrade header absent')
    count = 0
    while data:
        if len(data) < 2 or not data[1] & 128:
            raise AssertionError('HOST76 unmasked client WebSocket frame')
        size, offset = data[1] & 127, 2
        if size == 126:
            if len(data) < 4:
                raise AssertionError('HOST76 truncated client frame')
            size, offset = int.from_bytes(data[2:4], 'big'), 4
        elif size == 127:
            if len(data) < 10:
                raise AssertionError('HOST76 truncated client frame')
            size, offset = int.from_bytes(data[2:10], 'big'), 10
        end = offset + 4 + size
        if len(data) < end:
            raise AssertionError('HOST76 truncated masked payload')
        data = data[end:]
        count += 1
    return count


class GoSendTransport76Test(unittest.TestCase):
    def test_native_linux_owner_and_tls(self):
        # Future ROOT-only invocation. Actual Linux/root requirements are not
        # simulated on Windows and are not assertions about the P011 platform.
        self.assertEqual('linux', sys.platform)
        self.assertEqual(0, os.geteuid())
        self.assertTrue(os.path.isfile(OPENSSL))
        self.assertTrue(os.access(OPENSSL, os.X_OK))
        self.assertGreater(socket.if_nametoindex('lo'), 0)
        definitions = _Definitions()
        module = definitions.native
        original_worker = threading.current_thread()
        original_send = ssl.SSLSocket.send
        original_tls_close, original_raw_close = ssl.SSLSocket.close, socket.socket.close
        original_listen = socket.socket.listen
        original_select = definitions.pump.select.select
        private = tempfile.mkdtemp(prefix='host76-kernel-private-')
        private_metadata = os.lstat(private)
        prepared = fixture = peer = pump = None
        wire, tls_closes, raw_closes, listen_calls, terminal_writes = {}, {}, {}, [], []
        events = []
        removed, concurrent = False, False
        primary, cleanup_failures = None, []
        self._host76_primary = None
        self._host76_cleanup_failures = ()
        self._host76_failure_originals = None
        self._host76_failure_projection = None
        select_samples, step_samples = [], []
        original_end = None

        def retained_sample(history, sample):
            # PRIVATE diagnostic ring only, never Native/Pump ownership rows.
            history.append(sample)
            if len(history) > 32:
                del history[2]  # First two plus most recent thirty.

        def socket_role(raw):
            if pump is None:
                return 'before_pump'
            if raw is pump.listener:
                return 'listener'
            for index, row in enumerate(pump.connections):
                if raw is row.tls:
                    return ('ws' if row is pump._ws else
                            'download' if row is pump._download else 'connection_%d' % index)
            return 'other'

        def selected_interest(read, write, exceptional, wait):
            # Transparent actual select forward. Original returned lists/objects
            # are retained, not synthetic readiness or permission.
            if threading.current_thread() is not original_worker:
                return original_select(read, write, exceptional, wait)
            sample = {'entered': time.monotonic(), 'ended': None, 'wait': wait,
                      'read_original': tuple(read), 'write_original': tuple(write),
                      'read_roles': tuple(socket_role(raw) for raw in read),
                      'write_roles': tuple(socket_role(raw) for raw in write),
                      'returned': None, 'ready_read_roles': None, 'ready_write_roles': None}
            retained_sample(select_samples, sample)
            try:
                returned = original_select(read, write, exceptional, wait)
                sample['returned'] = returned
                sample['ready_read_roles'] = tuple(socket_role(raw) for raw in returned[0])
                sample['ready_write_roles'] = tuple(socket_role(raw) for raw in returned[1])
                return returned
            finally:
                sample['ended'] = time.monotonic()

        def peer_original_failure():
            if peer is not None and peer.done.is_set() and peer.errors:
                error = peer.errors[0]
                raise error.with_traceback(error.__traceback__)

        def retain_failure_projection():
            # No owner.check, socket IO, credentials or byte buffer contents.
            # Passive original references are retained separately from JSON.
            self._host76_failure_originals = (
                pump, fixture, peer, tuple(select_samples), tuple(step_samples),
                () if peer is None else tuple((error, error.__traceback__) for error in peer.errors))
            value = {'observed': time.monotonic(), 'original_until': original_end,
                     'pump': None if pump is None else pump.status(),
                     'connections': [], 'native_rows': [], 'select': [], 'steps': [],
                     'peer': None}
            if pump is not None:
                for row in pump.connections:
                    value['connections'].append({
                        'role': 'ws' if row is pump._ws else 'download' if row is pump._download else 'unassigned',
                        'phase': row.phase, 'ws_stage': row.ws_stage, 'fd': row.fd,
                        'rx_bytes': len(row.rx), 'tx_bytes': len(row.tx),
                        'tx_offset': row.tx_offset, 'after_flush': row.after_flush,
                        'handshake_want': row.handshake_want, 'read_want': row.read_want,
                        'write_want': row.write_want, 'accepted': row.accept_returned,
                        'wrapped': row.wrap_returned, 'close_called': row.close_called,
                        'closed': row.closed})
            if fixture is not None and fixture.native is not None:
                for row in fixture.native._send_tcp_rows_v75:
                    value['native_rows'].append({
                        'role': row._tcp_role_v76, 'fd': row.fd, 'returned': row.returned,
                        'unknown': row.unknown, 'attempted': row.attempted, 'closed': row.closed,
                        'accept_called': row._tcp_accept_called_v76,
                        'accept_delivered': row._tcp_accept_delivered_v76,
                        'wrap_called': row._tcp_wrap_called_v76,
                        'wrap_returned': row._tcp_wrap_returned_v76,
                        'wrap_delivered': row._tcp_wrap_delivered_v76,
                        'listen_called': row._tcp_listen_called_v76,
                        'listen_returned': row._tcp_listen_returned_v76})
            chosen = list(range(min(2, len(select_samples))))
            chosen += [index for index in range(max(2, len(select_samples) - 2), len(select_samples))]
            for index in chosen:
                sample = select_samples[index]
                value['select'].append({key: sample[key] for key in (
                    'entered', 'ended', 'wait', 'read_roles', 'write_roles',
                    'ready_read_roles', 'ready_write_roles')})
            chosen = list(range(min(2, len(step_samples))))
            chosen += [index for index in range(max(2, len(step_samples) - 2), len(step_samples))]
            value['steps'] = [step_samples[index] for index in chosen]
            if peer is not None:
                value['peer'] = {'phase': peer.phase, 'phase_times': tuple(peer.phase_times),
                    'events': tuple(peer.events), 'done': peer.done.is_set(),
                    'errors': [{'type': type(error).__name__,
                        'traceback': ''.join(traceback.format_exception(
                            type(error), error, error.__traceback__))[:4096]}
                        for error in peer.errors[:2]]}
            self._host76_failure_projection = value

        def kernel_listen(raw, backlog):
            # Transparent syscall instrumentation, not a new Native wrapper or
            # successful-return stub. This verifies prelisten isn't repeated.
            listen_calls.append((raw, backlog, threading.current_thread()))
            return original_listen(raw, backlog)

        def tls_close(raw):
            tls_closes[raw] = tls_closes.get(raw, 0) + 1
            return original_tls_close(raw)

        def raw_close(raw):
            raw_closes[raw] = raw_closes.get(raw, 0) + 1
            return original_raw_close(raw)

        def tls_send(raw, data, flags=0):
            owned = fixture is not None and any(
                row._tcp_tls_original_v76 is raw for row in fixture.native._send_accepted_rows_v76)
            connection = None if pump is None else next(
                (row for row in pump.connections if row.tls is raw), None)
            terminal = owned and connection is not None and connection.after_flush == 'terminal'
            if owned:
                self.assertIs(threading.current_thread(), original_worker)
            if terminal:
                self.assertIsNone(pump.result)
                self.assertIs(pump._download_complete, True)
                self.assertEqual(pump.archive_size, pump._downloaded)
                self.assertIs(pump._download.closed, True)
                native_download = [row for row in fixture.native._send_accepted_rows_v76
                                   if row._tcp_raw_original_v76 is pump._download.raw]
                self.assertEqual(1, len(native_download))
                self.assertIs(native_download[0].closed, True)
                self.assertIs(native_download[0].unknown, False)
                self.assertIs(native_download[0]._tcp_raw_close_returned_v76, True)
            sent = original_send(raw, data, flags)
            wire.setdefault(raw, bytearray()).extend(data[:sent])
            if terminal:
                terminal_writes.append(sent)
            return sent

        try:
            # One normal new Native76 path, no replay of six previous pump cases.
            original_end = time.monotonic() + 25.0
            prepared = object.__new__(_PreparedInput)
            prepared.__init__(definitions, private, original_end)
            fixture = object.__new__(_NativeAntecedents)
            fixture.__init__(definitions, original_end, prepared.cleanup_until)
            n, basis = fixture.native, fixture.basis
            self.assertIs(threading.current_thread(), fixture.worker)
            self.assertIs(type(basis), module.GoSendBasis)
            self.assertIs(type(fixture.server), definitions.modules['mta_go_dhcp'].GoDhcpServer)
            self.assertIs(type(fixture.core), definitions.modules['mta_dhcp'].SingleClientServer)
            self.assertIs(fixture.server._context(), n.dhcp_binding)
            self.assertEqual('lo', basis.origin.name)
            self.assertEqual(9, basis.origin.iftype)  # Explicit synthetic GO ancestry.
            self.assertEqual(0x7f000001, basis.binding.server_ip)
            self.assertEqual(0x7f000002, basis.binding.client_ip)

            with mock.patch.object(socket.socket, 'listen', kernel_listen), \
                    mock.patch.object(ssl.SSLSocket, 'send', tls_send), \
                    mock.patch.object(ssl.SSLSocket, 'close', tls_close), \
                    mock.patch.object(socket.socket, 'close', raw_close), \
                    mock.patch.object(definitions.pump.select, 'select', selected_interest):
                listener = n.open_send_listener(basis, original_end)
                self.assertIs(type(listener), module.GoSendListener)
                self.assertEqual(('127.0.0.1', listener.port), listener.endpoint)
                self.assertGreater(listener.port, 0)
                self.assertEqual(1, len(fixture.io.pre_factory_inventory))
                self.assertIs(fixture.io.pre_factory_inventory[0][-1], listener.row)
                self.assertIs(listener.row._tcp_factory_called_v75, True)
                self.assertIs(listener.row.returned, True)
                self.assertEqual(_metadata(os.fstat(listener.fd)), listener.metadata)
                self.assertTrue(stat.S_ISSOCK(listener.metadata[2]))
                self.assertEqual(b'lo\0', listener.raw.getsockopt(socket.SOL_SOCKET, 25, 16))
                self.assertEqual(0, listener.raw.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
                self.assertIs(listener.raw.get_inheritable(), False)
                self.assertEqual(0.0, listener.raw.gettimeout())
                self.assertIs(n.listen_send_listener(basis, listener, original_end), listener)
                self.assertEqual(1, listener.raw.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
                self.assertIs(listener.row._tcp_listen_called_v76, True)
                self.assertIs(listener.row._tcp_listen_returned_v76, True)
                self.assertEqual([(listener.raw, 2, original_worker)], listen_calls)

                # Selected DeviceInfo MAC != link station MAC. The actual new
                # parser + two stable STA tables + final STA resolve that map.
                native_peer = n.issue_send_peer(basis, fixture.selected_text, original_end)
                self.assertIs(type(native_peer), module.GoSendPeer)
                self.assertEqual(fixture.selected, native_peer.selected_mac)
                self.assertEqual(fixture.station, native_peer.station[0])
                self.assertNotEqual(native_peer.station[0], native_peer.selected_mac)
                self.assertIs(native_peer.allocation, fixture.allocation)
                self.assertIs(native_peer.core, fixture.core)
                self.assertIs(native_peer.core_key, fixture.core.key)
                self.assertIs(native_peer.service_tuple, n._dhcp_service_original)
                self.assertIs(native_peer.canonical, fixture.store.current)
                self.assertEqual(((fixture.station_raw, b''), (fixture.station_raw, b'')),
                                 native_peer.raw_tables)
                self.assertEqual(2, fixture.control_queries.count(b'STA-FIRST'))
                self.assertEqual(2, fixture.control_queries.count(b'STA-NEXT 02:10:20:30:40:50'))
                self.assertEqual(2, fixture.control_queries.count(b'STA 02:10:20:30:40:50'))
                owner = n.issue_send_owner(basis, listener, native_peer, original_end)
                self.assertIs(type(owner), module.GoSendPumpOwner)
                self.assertIs(owner.worker, original_worker)
                self.assertIs(owner.mutex, fixture.mutex)
                self.assertEqual(original_end, owner.end)
                owner_end = owner.end
                pump = definitions.pump.SenderPump(listener.raw, prepared.archive,
                    prepared.prepared.archive_size, prepared.prepared.file_count,
                    prepared.prepared.total_bytes, prepared.prepared.request_payload,
                    prepared.prepared.tls_context, owner, owner_end,
                    progress=lambda state, details: events.append((state, dict(details))))
                self.assertIs(pump.start(), pump)
                self.assertEqual([(listener.raw, 2, original_worker)], listen_calls)
                # Actual empty nonblocking accept, not a mocked EAGAIN boolean.
                self.assertIsNone(owner.accept(listener.raw, owner_end))
                no_fd = n._send_last_accept_row_v76
                self.assertIs(no_fd._tcp_accept_called_v76, True)
                self.assertIs(no_fd.returned, False)
                self.assertIs(no_fd.attempted, True)
                self.assertIs(no_fd.closed, True)
                self.assertIs(no_fd.unknown, False)
                self.assertIsNone(no_fd.fd)
                self.assertIsInstance(no_fd.failure, OSError)
                self.assertIn(no_fd.failure.errno, (errno.EAGAIN, errno.EWOULDBLOCK))
                peer = _PhonePeer(definitions, listener.port, 'host76-kernel-task', owner_end)
                peer.start()  # The ONLY created test thread; never a server thread.
                with mock.patch.object(threading.Thread, 'start', side_effect=_forbidden) as server_thread:
                    while pump.state not in ('completed', 'cancelled', 'failed'):
                        peer_original_failure()
                        if time.monotonic() >= owner_end:
                            raise AssertionError('HOST76 original transfer deadline expired')
                        sample = {'entered': time.monotonic(), 'ended': None, 'returned': False}
                        retained_sample(step_samples, sample)
                        try:
                            pump.step(0.02)
                            sample['returned'] = True
                        finally:
                            sample['ended'] = time.monotonic()
                        peer_original_failure()
                        if pump._download is not None and not pump._download.closed and \
                                pump._ws is not None and not pump._ws.closed and pump._downloaded > 0:
                            concurrent = True
                        self.assertIs(owner.end, owner_end)
                        self.assertEqual(original_end, basis.end)
                        for row in n._send_accepted_rows_v76:
                            self.assertIs(row._tcp_accept_delivered_v76, True)
                            self.assertEqual('127.0.0.2', row._tcp_accept_value_v76[1][0])
                            if not row.closed:
                                self.assertEqual(_metadata(os.fstat(row.fd)), row.metadata)
                                self.assertEqual(b'lo\0', row.value.getsockopt(socket.SOL_SOCKET, 25, 16))
                                self.assertIs(row.value.get_inheritable(), False)
                                self.assertEqual(0.0, row.value.gettimeout())
                                if row._tcp_wrap_delivered_v76:
                                    self.assertIs(row.value, row._tcp_tls_original_v76)
                                    self.assertEqual(-1, row._tcp_raw_original_v76.fileno())
                                    # Detach occurs while the actual original FD
                                    # still exists: it is NOT a close certificate.
                                    self.assertTrue(stat.S_ISSOCK(os.fstat(row.fd).st_mode))
                                    self.assertIs(row.attempted, False)
                    self.assertIs(pump.close(prepared.cleanup_until), True)
                    self.assertEqual(0, server_thread.call_count)
                self.assertTrue(peer.join())
                self.assertEqual([], peer.errors)
                self.assertIs(peer.done.is_set(), True)
                self.assertTrue(all(raw.fileno() == -1 for raw in peer.sockets))
                self.assertTrue(concurrent)
                self.assertIsNone(pump.failure)
                self.assertEqual('completed', pump.state)
                self.assertIs(pump.result['peer_completion_verified'], True)
                self.assertEqual(prepared.archive_bytes, peer.archive)
                self.assertEqual(hashlib.sha256(prepared.archive_bytes).digest(),
                                 hashlib.sha256(peer.archive).digest())
                with zipfile.ZipFile(io.BytesIO(peer.archive)) as archive:
                    self.assertIsNone(archive.testzip())
                    self.assertEqual([prepared.member], archive.namelist())
                    self.assertEqual(prepared.data, archive.read(prepared.member))
                self.assertEqual(['accepted', 'download_while_ws_open', 'download_complete', 'ack_received'],
                                 peer.events)
                self.assertEqual(peer.certificates[0], peer.certificates[1])
                self.assertEqual(3, _masked_frames(bytes(wire[peer.sockets[1]])))
                self.assertTrue(terminal_writes)
                self.assertEqual(2, len(n._send_accepted_rows_v76))
                self.assertIs(n._send_accepted_rows_v76, n._send_accepted_history_v76)
                self.assertTrue(all(row.closed for row in pump.history))
                self.assertIs(pump.status()['socket_cleanup_pending'], False)
                self.assertEqual(prepared.prepared.archive_size, pump.result['archiveBytesSent'])
                self.assertEqual(1, pump.result['fileCount'])
                self.assertEqual(len(prepared.data), pump.result['totalSize'])
                self.assertEqual([(listener.raw, 2, original_worker)], listen_calls)
                self.assertEqual(1, raw_closes[listener.raw])
                self.assertEqual(-1, listener.raw.fileno())
                self.assertIs(listener.row.closed, True)
                self.assertIs(listener.row.unknown, False)
                _ebadf(self, listener.fd)
                for row in n._send_accepted_rows_v76:
                    self.assertIs(type(row.value), ssl.SSLSocket)
                    self.assertIs(row.value, row._tcp_tls_original_v76)
                    self.assertIs(row._tcp_raw_original_v76, row._tcp_accept_value_v76[0])
                    self.assertIs(row._tcp_wrap_called_v76, True)
                    self.assertIs(row._tcp_wrap_returned_v76, True)
                    self.assertIs(row._tcp_wrap_delivered_v76, True)
                    self.assertIs(row.attempted, True)
                    self.assertIs(row.closed, True)
                    self.assertIs(row.unknown, False)
                    self.assertIsNone(row.close_failure)
                    self.assertIs(row._tcp_raw_close_called_v76, True)
                    self.assertIs(row._tcp_raw_close_returned_v76, True)
                    self.assertEqual(1, tls_closes[row._tcp_tls_original_v76])
                    self.assertEqual(1, raw_closes[row._tcp_raw_original_v76])
                    self.assertEqual(-1, row.value.fileno())
                    self.assertEqual(-1, row._tcp_raw_original_v76.fileno())
                    self.assertTrue(any(stat_event['fd'] == row.fd and stat_event['errno'] == errno.EBADF
                                        for stat_event in fixture.io.stats))
                    _ebadf(self, row.fd)
                raw_before, tls_before = dict(raw_closes), dict(tls_closes)
                self.assertIs(pump.close(prepared.cleanup_until), True)
                self.assertEqual(raw_before, raw_closes)
                self.assertEqual(tls_before, tls_closes)
                fixture.store.restore_attempted, fixture.store.restore_until = True, prepared.cleanup_until
                facts = n.close_send_inventory(prepared.cleanup_until)
                self.assertEqual(tuple((True, True) for row in n._send_tcp_rows_v75), facts)
                self.assertEqual(raw_before, raw_closes)
                self.assertEqual(tls_before, tls_closes)
                self.assertIs(prepared.archive.closed, False)
                # This is the only root-owned transport tested: loopback has no
                # GO radio or phone configuration despite synthetic iftype=9.
                self.assertEqual(original_end, n._dhcp_service_original[1])
        except BaseException as error:
            primary = (error, error.__traceback__)
            self._host76_primary = primary  # Same original, not a replacement.
            try:
                retain_failure_projection()  # BEFORE cleanup changes phases/FDs.
            except BaseException:
                self._host76_failure_projection = {'projection': 'unavailable'}
        finally:
            def close_pump():
                if pump is not None and not pump.listener_close_called:
                    self.assertIs(pump.close(prepared.cleanup_until), True)
            _capture_cleanup(cleanup_failures, 'pump', close_pump)

            def join_peer():
                if peer is not None and peer.thread is not None and peer.thread.is_alive():
                    self.assertTrue(peer.join())
            _capture_cleanup(cleanup_failures, 'peer_join', join_peer)

            def close_native_inventory():
                if fixture is not None and fixture.native is not None:
                    fixture.store.restore_attempted = True
                    fixture.store.restore_until = prepared.cleanup_until
                    fixture.native.close_send_inventory(prepared.cleanup_until)
            _capture_cleanup(cleanup_failures, 'native_tcp_inventory', close_native_inventory)

            def close_antecedents():
                if fixture is not None:
                    fixture.close_antecedent_sockets(self)
            _capture_cleanup(cleanup_failures, 'native_ancestor_inventory', close_antecedents)
            if fixture is not None:
                for fact in fixture.cleanup_failures:
                    if not any(error is fact[1] for unused, error, tb in cleanup_failures):
                        cleanup_failures.append(fact)
            if fixture is not None:
                # A raw returned to this fixture before adopt still belongs to
                # the fixture. Close the exact object only, without modifying
                # Native returned/closed/unknown flags or claiming its closure.
                for role in ('udp', 'ip_socket'):
                    def close_unadopted_raw(role=role):
                        raw = getattr(fixture, role, None)
                        if raw is not None and raw.fileno() != -1:
                            fd = raw.fileno()
                            raw.close()
                            self.assertEqual(-1, raw.fileno())
                            _ebadf(self, fd)
                    _capture_cleanup(cleanup_failures, 'fixture_raw_' + role, close_unadopted_raw)
                _capture_cleanup(cleanup_failures, 'fixture_lock', fixture.release_fixture_lock)

            def close_preparation():
                if prepared is not None:
                    prepared.close(self)
            _capture_cleanup(cleanup_failures, 'preparation_and_selection', close_preparation)
            if prepared is not None:
                for fact in prepared.cleanup_failures:
                    if not any(error is fact[1] for unused, error, tb in cleanup_failures):
                        cleanup_failures.append(fact)

            def remove_private_directory():
                nonlocal removed
                current = os.lstat(private)
                self.assertEqual((private_metadata.st_dev, private_metadata.st_ino),
                                 (current.st_dev, current.st_ino))
                # Unknown resources stay retained; deletion is never evidence
                # of closure. Only the exact new test directory may be removed.
                if not cleanup_failures:
                    shutil.rmtree(private)
                    removed = True
            _capture_cleanup(cleanup_failures, 'private_directory', remove_private_directory)
            self._host76_cleanup_failures = tuple(cleanup_failures)

        if primary is not None or cleanup_failures:
            # Failure raw is private under the ROOT checker. Bounded diagnostic
            # text cannot replace the original exception or allow the marker.
            try:
                text = 'HOST76_PRIVATE_DIAGNOSTIC ' + json.dumps(
                    self._host76_failure_projection, sort_keys=True, separators=(',', ':')) + '\n'
                text += 'HOST76_PRIVATE_CLEANUP count=%d primary=%d\n' % (
                    len(cleanup_failures), 1 if primary is not None else 0)
                for role, error, original_traceback in cleanup_failures:
                    text += 'CLEANUP ' + role + '\n'
                    text += ''.join(traceback.format_exception(type(error), error, original_traceback))
                sys.stderr.write(text.encode('utf-8')[:16384].decode('utf-8', 'ignore'))
            except BaseException:
                pass  # Original retained failure is still raised below.
        if primary is not None:
            error, original_traceback = primary
            raise error.with_traceback(original_traceback)
        if cleanup_failures:
            unused, error, original_traceback = cleanup_failures[0]
            raise error.with_traceback(original_traceback)
        self.assertTrue(removed)
        self.assertFalse(os.path.exists(private))
        print(MARKER, end='')


if __name__ == '__main__':
    unittest.main()

