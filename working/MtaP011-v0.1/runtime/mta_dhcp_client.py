# -*- coding: utf-8 -*-
"""Private broadcast-only DHCP adapter, NOT a production CLIENT/IP backend.

All dependencies/proofs are trusted internal coordinator seams, never UI data.
No IP/route/DNS/ARP writes, endpoint publication, raw sockets or service stops.
Python 3.5. The real owned CLIENT proof provider has not been implemented.
"""
import contextlib
import math
import re
import socket
import struct
import sys
import threading
import time
from collections import namedtuple

import mta_dhcp as wire
import mta_dhcp_client_core as core

IP_PKTINFO, SO_BINDTODEVICE, SO_REUSEPORT = 8, 25, 15
PKTINFO = struct.Struct('=I4s4s')
POLL_SECONDS, PROOF_SECONDS, MAX_SECONDS = 0.2, 0.2, 300
_RLOCK_TYPE = type(threading.RLock())
ClientAssociation = namedtuple('ClientAssociation', 'boot_id task_epoch native_epoch phy wdev ifindex ifname mac deadline receipt_id')
AssociationProof = namedtuple('AssociationProof', 'context boot_id task_epoch native_epoch phy wdev ifindex ifname iftype '
    'association_verified owner_verified receipt_fsynced persistent_readback_verified baseline_verified ipv4_unconfigured')
RunnerTicket = namedtuple('RunnerTicket', 'client context thread creator generation')
RunnerClosedProof = namedtuple('RunnerClosedProof', 'client context ticket creator generation all_producers_stopped')
ConfigurationCandidate = namedtuple('ConfigurationCandidate', 'allocation interface_configured endpoint_verified')
ERRORS = frozenset(('invalid_time', 'invalid_association', 'invalid_callbacks', 'invalid_lock', 'invalid_deadline',
    'closed', 'clock_failed', 'clock_backwards', 'cancel_invalid', 'cancelled', 'expired', 'proof_failed',
    'proof_budget', 'proof_unverified', 'lock_timeout', 'invalid_socket_api', 'socket_open_failed',
    'socket_options', 'socket_binding', 'socket_inheritance', 'socket_timeout', 'socket_io_failed',
    'short_send', 'concurrent_operation', 'invalid_state', 'packet_budget', 'invalid_runner', 'runner_proof_failed'))
IGNORES = frozenset(('packet_invalid', 'source_invalid', 'pktinfo_invalid', 'server_identity_mismatch', 'dhcp_invalid'))


class DhcpSocketClientError(RuntimeError):
    def __init__(self, reason):
        RuntimeError.__init__(self, reason if type(reason) is str and reason in ERRORS else 'socket_io_failed')


def _number(value):
    if type(value) not in (int, float) or not 0 <= value <= 2 ** 53 or not math.isfinite(value):
        raise DhcpSocketClientError('invalid_time')
    return float(value)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


class DhcpSocketClient:
    """Synchronous open/poll; caller owns capsule before any producer starts.

    proof_callback(context,budget) must freshly prove exact boot/epochs/native
    tuple, persisted association ownership, original baseline and NO IPv4 on
    this CLIENT. It runs under the common lease RLock, bounded by contract.
    Arbitrary callbacks/OS IO are not forcibly preemptible. Unknown factory
    failures stay pending; this module deliberately offers no clearing bypass.
    """
    def __init__(self, context, proof_callback, cancelled, ownership_lock,
                 clock=None, socket_factory=None, if_nametoindex=None, xid=None):
        if (type(context) is not ClientAssociation or type(context.boot_id) is not str or
                re.match(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z', context.boot_id) is None or
                not _integer(context.task_epoch, 1, 2 ** 53) or not _integer(context.native_epoch, 1, 2 ** 53) or
                not _integer(context.phy, 0, 65535) or not _integer(context.wdev, 1, 2 ** 64 - 1) or
                not _integer(context.ifindex, 1, 2 ** 31 - 1) or type(context.ifname) is not str or
                re.match(r'^mta[0-9a-f]{8}\Z', context.ifname) is None or
                type(context.receipt_id) is not str or re.match(r'^[0-9a-f]{64}\Z', context.receipt_id) is None):
            raise DhcpSocketClientError('invalid_association')
        if type(ownership_lock) is not _RLOCK_TYPE:raise DhcpSocketClientError('invalid_lock')
        self._clock = clock or time.monotonic
        self._factory = socket_factory or socket.socket
        self._real_factory = socket_factory is None
        self._index_reader = if_nametoindex or getattr(socket, 'if_nametoindex', None)
        if not all(callable(value) for value in (proof_callback, cancelled, self._clock, self._factory, self._index_reader)):
            raise DhcpSocketClientError('invalid_callbacks')
        now = _number(self._clock()); deadline = _number(context.deadline)
        if not 1 <= deadline - now <= MAX_SECONDS:raise DhcpSocketClientError('invalid_deadline')
        try:self._core = core.DynamicClientExchange(context.mac, deadline, xid=xid)
        except core.DhcpClientError:raise DhcpSocketClientError('invalid_association') from None
        self._context = context; self._proof_callback = proof_callback; self._cancelled = cancelled
        self._owner = ownership_lock; self._lock = threading.RLock(); self._last_now = now
        self._socket = None; self._candidate_socket = None; self._pending_close = []; self._closers = []
        self._opening = False; self._active = False; self._proofs = 0; self._factory_unknown = False
        self._closing = False; self._generation = 0; self._stage = 'new'; self._reason = 'not_opened'
        self._received = 0; self._sent = 0; self._ignored = 0; self._ticket = None; self._runner_active = False

    @property
    def context(self):return self._context

    def _require_producer(self):
        """Every non-main producer retains its ticket past method return."""
        thread = threading.current_thread()
        if thread is threading.main_thread():return
        with self._lock:
            ticket = self._ticket
            if (type(ticket) is not RunnerTicket or ticket.client is not self or ticket.context is not self.context or
                    ticket.thread is not thread or ticket.creator is None or ticket.generation != self._generation):
                self._abort('invalid_runner')

    def _now(self):
        try:now = _number(self._clock())
        except Exception:self._abort('clock_failed')
        with self._lock:
            if now < self._last_now:self._abort('clock_backwards')
            self._last_now = now
        return now

    def _abort(self, reason):
        with self._lock:self._reason = reason
        self.close(); raise DhcpSocketClientError(reason)

    def _basic(self, generation):
        with self._lock:
            if self._closing or generation != self._generation:raise DhcpSocketClientError('closed')
        now = self._now()
        try:cancelled = self._cancelled()
        except Exception:self._abort('cancel_invalid')
        if type(cancelled) is not bool:self._abort('cancel_invalid')
        if cancelled:self._abort('cancelled')
        if now >= self.context.deadline:self._abort('expired')
        return now

    @contextlib.contextmanager
    def _guard(self, generation):
        with self._lock:self._proofs += 1
        acquired = False
        try:
            self._basic(generation)
            acquired = self._owner.acquire(timeout=PROOF_SECONDS)
            if not acquired:self._abort('lock_timeout')
            start = self._basic(generation)
            try:proof = self._proof_callback(self.context, PROOF_SECONDS); index = self._index_reader(self.context.ifname)
            except Exception:self._abort('proof_failed')
            now = self._basic(generation)
            if now - start > PROOF_SECONDS:self._abort('proof_budget')
            expected = tuple(getattr(self.context, key) for key in ('boot_id','task_epoch','native_epoch','phy','wdev','ifindex','ifname'))
            if (type(proof) is not AssociationProof or proof.context is not self.context or
                    type(proof.boot_id) is not str or type(proof.ifname) is not str or
                    tuple(getattr(proof, key) for key in ('boot_id','task_epoch','native_epoch','phy','wdev','ifindex','ifname')) != expected or
                    any(type(getattr(proof, key)) is not int for key in ('task_epoch','native_epoch','phy','wdev','ifindex')) or
                    type(proof.iftype) is not int or proof.iftype != 8 or type(index) is not int or index != self.context.ifindex or
                    any(flag is not True for flag in proof[9:])):
                self._abort('proof_unverified')
            yield now
            self._basic(generation)
        finally:
            if acquired:self._owner.release()
            with self._lock:self._proofs -= 1

    def _dispose(self, raw):
        with self._lock:
            if any(value is raw for value in self._closers):return False
            self._closers.append(raw)
        verified = False
        try:
            try:raw.close()
            except Exception:pass
            try:descriptor = raw.fileno(); verified = type(descriptor) is int and descriptor == -1
            except Exception:pass
            with self._lock:
                self._pending_close = [value for value in self._pending_close if value is not raw]
                if not verified:self._pending_close.append(raw)
            return verified
        finally:
            with self._lock:self._closers = [value for value in self._closers if value is not raw]

    def close(self):
        """Intent only until every exact FD AND producer/proof actor is closed.

        A reserved runner needs an external trusted closure proof. Factory
        exceptions can conceal a resource; they remain pending permanently.
        A finite timeout is not a claim that arbitrary IO/callbacks are dead.
        """
        with self._lock:
            if not self._closing:self._generation += 1
            self._closing = True; self._core.cancel()
            resources = list(self._pending_close)
            for value in (self._socket, self._candidate_socket):
                if value is not None and all(old is not value for old in resources):resources.append(value)
            self._socket = self._candidate_socket = None
            if self._reason in ('not_opened','broadcast_dora'):self._reason = 'closed_by_owner'
        for value in resources:self._dispose(value)
        with self._lock:
            complete = not (self._opening or self._active or self._proofs or self._closers or self._pending_close or
                            self._factory_unknown or self._runner_active or self._ticket is not None)
            self._stage = 'closed' if complete else 'closing'
            return complete

    cancel = close

    def _options(self, raw):
        try:
            device = raw.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)
            if type(device) is not bytes or device.rstrip(b'\0') != self.context.ifname.encode('ascii'):
                raise DhcpSocketClientError('socket_options')
            for level, option, expected in ((socket.SOL_SOCKET,socket.SO_TYPE,socket.SOCK_DGRAM),
                    (socket.SOL_SOCKET,socket.SO_REUSEADDR,0),(socket.SOL_SOCKET,SO_REUSEPORT,0),
                    (socket.SOL_SOCKET,socket.SO_BROADCAST,1),(socket.IPPROTO_IP,IP_PKTINFO,1)):
                value = raw.getsockopt(level, option)
                if type(value) is not int or value != expected:raise DhcpSocketClientError('socket_options')
        except DhcpSocketClientError:raise
        except Exception:raise DhcpSocketClientError('socket_options') from None

    def _send(self, raw, packet, generation):
        with self._guard(generation):
            self._options(raw)
            if raw.getsockname() != ('0.0.0.0',68):self._abort('socket_binding')
            with self._lock:
                if self._closing or generation != self._generation:self._abort('closed')
            # Linearized under the shared lease lock. Cancellation can leave
            # in-flight IO; its actor prevents restore until it really returns.
            count = raw.sendmsg([packet], [(socket.IPPROTO_IP,IP_PKTINFO,PKTINFO.pack(self.context.ifindex,wire.ZERO,wire.ZERO))],
                                0, ('255.255.255.255',67))
            if type(count) is not int or count != len(packet):self._abort('short_send')
            with self._lock:self._sent += 1

    def open(self):
        self._require_producer()
        with self._lock:
            if self._stage != 'new' or self._closing:self._abort('invalid_state')
            self._opening = True; self._stage = 'opening'; generation = self._generation
        raw = None
        try:
            with self._guard(generation):
                if self._real_factory and not sys.platform.startswith('linux'):self._abort('invalid_socket_api')
                if not callable(getattr(socket,'CMSG_SPACE',None)):self._abort('invalid_socket_api')
            with self._lock:
                if self._closing or generation != self._generation:raise DhcpSocketClientError('closed')
                self._factory_unknown = True
            raw = self._factory(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
            with self._lock:
                self._candidate_socket = raw
                if raw is not None and callable(getattr(raw,'close',None)) and callable(getattr(raw,'fileno',None)):
                    self._factory_unknown = False
            with self._guard(generation):
                required = ('sendmsg','recvmsg','getsockopt','setsockopt','settimeout','gettimeout','get_inheritable','set_inheritable')
                # Python socket.family can be an AddressFamily IntEnum; a
                # boolean is never a kernel family value.
                if (raw is None or not isinstance(raw.family,int) or isinstance(raw.family,bool) or raw.family != socket.AF_INET or
                        not all(callable(getattr(raw,key,None)) for key in required) or
                        type(raw.fileno()) is not int or raw.fileno() < 0):self._abort('invalid_socket_api')
                raw.set_inheritable(False)
                if raw.get_inheritable() is not False:self._abort('socket_inheritance')
                raw.setsockopt(socket.SOL_SOCKET,SO_BINDTODEVICE,self.context.ifname.encode('ascii') + b'\0')
                raw.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); raw.setsockopt(socket.IPPROTO_IP,IP_PKTINFO,1)
                raw.settimeout(POLL_SECONDS)
                if raw.gettimeout() != POLL_SECONDS:self._abort('socket_timeout')
                self._options(raw); raw.bind(('0.0.0.0',68))
                if raw.getsockname() != ('0.0.0.0',68):self._abort('socket_binding')
                self._options(raw)
                with self._lock:
                    if self._closing or generation != self._generation:self._abort('closed')
                    self._socket = raw; self._candidate_socket = None; self._stage = 'selecting'; self._reason = 'broadcast_dora'
                packet = self._core.start(self._now())
            self._send(raw,packet,generation); return self
        except DhcpSocketClientError:
            self.close(); raise
        except Exception:self._abort('socket_open_failed')
        finally:
            with self._lock:dispose = raw is not None and (self._closing or self._socket is not raw)
            if dispose:self._dispose(raw)
            with self._lock:
                if self._candidate_socket is raw:self._candidate_socket = None
                self._opening = False

    def _envelope(self, packet, ancillary, flags, source):
        if type(packet) is not bytes or not 240 <= len(packet) <= wire.MAX_PACKET or type(flags) is not int or flags != 0:
            return 'packet_invalid'
        if type(source) is not tuple or len(source) != 2 or type(source[1]) is not int or source[1] != 67:return 'source_invalid'
        try:origin = wire.ipv4(source[0])
        except wire.DhcpError:return 'source_invalid'
        if not wire._private(origin):return 'source_invalid'
        if type(ancillary) is not list or len(ancillary) != 1:return 'pktinfo_invalid'
        row = ancillary[0]
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not int or type(row[1]) is not int or
                row[:2] != (socket.IPPROTO_IP,IP_PKTINFO) or type(row[2]) is not bytes or len(row[2]) != PKTINFO.size):return 'pktinfo_invalid'
        index, local, destination = PKTINFO.unpack(row[2])
        if index != self.context.ifindex or local != wire.ZERO or destination != b'\xff'*4:return 'pktinfo_invalid'
        try:message = wire.decode(packet)
        except wire.DhcpError:return 'dhcp_invalid'
        # Restricted no-relay profile. This is DHCP consistency, NOT endpoint
        # authentication; neither UDP source nor option54 proves the MTA GO IP.
        if message['options'].get(54) != origin:return 'server_identity_mismatch'
        return None

    def poll(self):
        self._require_producer()
        with self._lock:
            if self._active:self._abort('concurrent_operation')
            if self._closing or self._socket is None:self._abort('invalid_state')
            self._active = True; raw = self._socket; generation = self._generation
        try:
            with self._guard(generation) as now:
                self._options(raw)
                if raw.getsockname() != ('0.0.0.0',68):self._abort('socket_binding')
                wait = min(POLL_SECONDS,self.context.deadline - now)
                raw.settimeout(wait)
                if raw.gettimeout() != wait:self._abort('socket_timeout')
            try:packet, ancillary, flags, source = raw.recvmsg(wire.MAX_PACKET + 1,socket.CMSG_SPACE(PKTINFO.size),0)
            except socket.timeout:packet = None
            with self._guard(generation) as now:
                reply = None
                if packet is not None:
                    with self._lock:self._received += 1
                    if self._received > 64:self._abort('packet_budget')
                    reason = self._envelope(packet,ancillary,flags,source)
                    if reason is not None:
                        with self._lock:self._ignored += 1
                        return {'event':'ignored','reason':reason}
                    try:
                        stage = self._core.status(now)['stage']
                        if stage == 'selecting':reply = self._core.accept_offer(packet,now)
                        elif stage == 'requesting':self._core.accept_ack(packet,now)
                        else:return {'event':'ignored','reason':'dhcp_invalid'}
                    except core.DhcpClientError as error:
                        if self._core.status(now)['stage'] in core.TERMINAL:self._abort('invalid_state')
                        with self._lock:self._ignored += 1
                        return {'event':'ignored','reason':'dhcp_invalid'}
                else:reply = self._core.tick(now)
                status = self._core.status(now)
                if status['stage'] in core.TERMINAL:self._abort('expired')
                with self._lock:self._stage = status['stage']
            if reply is not None:self._send(raw,reply,generation)
            return {'event':'candidate_received' if status['stage'] == 'bound' else 'waiting','reason':'allocation_not_verified'}
        except DhcpSocketClientError:
            self.close(); raise
        except Exception:self._abort('socket_io_failed')
        finally:
            with self._lock:self._active = False

    def candidate(self):
        """PRIVATE, current allocation only; never an IP/endpoint permission."""
        self._require_producer()
        with self._lock:generation = self._generation
        with self._guard(generation) as now:
            with self._lock:
                value = self._core.configuration(now)
                return None if value is None else ConfigurationCandidate(value,False,False)

    def reserve_runner(self, thread, creator):
        """Coordinator registers exact producer BEFORE attempting Thread.start."""
        with self._lock:
            if (type(thread) is not threading.Thread or thread.ident is not None or creator is None or
                    self._ticket is not None or self._closing or self._stage != 'new'):self._abort('invalid_runner')
            self._ticket = RunnerTicket(self,self.context,thread,creator,self._generation)
            return self._ticket

    def run(self, ticket):
        with self._lock:
            if (ticket is not self._ticket or type(ticket) is not RunnerTicket or ticket.thread is not threading.current_thread() or
                    self._closing or ticket.generation != self._generation):self._abort('invalid_runner')
            self._runner_active = True
        try:
            self.open()
            while True:
                self.poll()
                value = self.candidate()
                if value is not None:return value
        finally:
            self.close()
            with self._lock:self._runner_active = False

    def confirm_runner_closed(self, ticket, creator, proof_callback):
        """External session proves start cannot occur/is joined; never joins.

        Exact client/context/ticket/creator/current generation and actual dead
        thread are required. A generic True cannot resolve a late producer.
        """
        with self._lock:
            if (not self._closing or type(ticket) is not RunnerTicket or ticket is not self._ticket or creator is not ticket.creator or
                    self._runner_active or ticket.thread.is_alive() or not callable(proof_callback)):return False
            generation = self._generation; self._proofs += 1
        acquired = False
        try:
            acquired = self._owner.acquire(timeout=PROOF_SECONDS)
            if not acquired:return False
            start = self._now()
            try:proof = proof_callback(self,self.context,ticket,creator,generation,PROOF_SECONDS)
            except Exception:return False
            if self._now() - start > PROOF_SECONDS:return False
            with self._lock:
                valid = (type(proof) is RunnerClosedProof and proof.client is self and proof.context is self.context and
                    proof.ticket is ticket and proof.creator is creator and type(proof.generation) is int and proof.generation == generation and
                    proof.all_producers_stopped is True and generation == self._generation and ticket is self._ticket and
                    not self._runner_active and not ticket.thread.is_alive())
                if valid:self._ticket = None
                return valid
        finally:
            if acquired:self._owner.release()
            with self._lock:self._proofs -= 1

    def status(self):
        with self._lock:
            pending = bool(self._opening or self._active or self._proofs or self._closers or self._pending_close or
                           self._factory_unknown or self._runner_active or self._ticket is not None)
            stage = ('closing' if pending else 'closed') if self._closing else self._stage
            return {'stage':stage,'reason':self._reason,'packets_received':self._received,'packets_ignored':self._ignored,
                    'requests_transmitted':self._sent,'socket_actor_pending':pending,'factory_resources_unknown':self._factory_unknown,
                    'runner_producer_pending':self._ticket is not None,'socket_close_verified':self._closing and not pending,
                    'interface_configured':False,'endpoint_verified':False,'send_available':False,'receive_available':False}
