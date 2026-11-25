"""HOST mocks only: no real sockets, radios, IP writes or CLIENT provider."""
import ast
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT / 'runtime'))
import mta_dhcp_client as adapter
from tests import test_dhcp_client_core as fixture
import mta_dhcp as wire


def setUpModule():
    # Explicit HOST Linux ancillary-size seam, never a production fallback.
    global _CMSG_PATCH
    _CMSG_PATCH = mock.patch.object(socket,'CMSG_SPACE',lambda size:16 + ((size + 7) // 8) * 8,create=True)
    _CMSG_PATCH.start()


def tearDownModule():
    _CMSG_PATCH.stop()


def context(**changes):
    fields = dict(boot_id='00000000-0000-0000-0000-000000000001',task_epoch=1,native_epoch=2,phy=0,wdev=7,
                  ifindex=9,ifname='mta1234abcd',mac=fixture.MAC,deadline=100.0,receipt_id='a'*64)
    fields.update(changes); return adapter.ClientAssociation(**fields)


def proof(ctx, **changes):
    fields = dict(context=ctx,boot_id=ctx.boot_id,task_epoch=ctx.task_epoch,native_epoch=ctx.native_epoch,
                  phy=ctx.phy,wdev=ctx.wdev,ifindex=ctx.ifindex,ifname=ctx.ifname,iftype=8,
                  association_verified=True,owner_verified=True,receipt_fsynced=True,
                  persistent_readback_verified=True,baseline_verified=True,ipv4_unconfigured=True)
    fields.update(changes); return adapter.AssociationProof(**fields)


def packet(kind=wire.OFFER, **changes):
    return fixture.response(kind=kind,**changes)


def envelope(payload=None, index=9, local=wire.ZERO, destination=b'\xff'*4, source=None, flags=0, ancillary=None):
    return (packet() if payload is None else payload,
            [(socket.IPPROTO_IP,adapter.IP_PKTINFO,adapter.PKTINFO.pack(index,local,destination))] if ancillary is None else ancillary,
            flags,(fixture.SERVER,67) if source is None else source)


class FakeSocket:
    def __init__(self):
        self.family = socket.AF_INET; self.fd = 10; self.options = {}; self.timeout = None
        self.inheritable = True; self.address = None; self.sent = []; self.received = []
        self.close_count = 0; self.action = None; self.on_recv = None; self.on_send = None
    def fileno(self):return self.fd
    def close(self):
        self.close_count += 1
        if self.action == 'close_fail':raise OSError('HOST_PRIVATE_CLOSE')
        self.fd = -1
    def set_inheritable(self,value):self.inheritable = value
    def get_inheritable(self):return True if self.action == 'inherit' else self.inheritable
    def setsockopt(self,level,option,value):self.options[(level,option)] = value
    def getsockopt(self,level,option,*unused):
        if option == socket.SO_TYPE:return int(socket.SOCK_DGRAM)
        if option in (socket.SO_REUSEADDR,adapter.SO_REUSEPORT):return 1 if self.action == 'reuse' else 0
        value = self.options.get((level,option))
        if self.action == 'device' and option == adapter.SO_BINDTODEVICE:return b'wlan0\0'
        if self.action == 'pktinfo' and option == adapter.IP_PKTINFO:return 0
        if self.action == 'broadcast' and option == socket.SO_BROADCAST:return 0
        return value
    def settimeout(self,value):self.timeout = value
    def gettimeout(self):return None if self.action == 'timeout' else self.timeout
    def bind(self,address):
        if self.action == 'port_conflict':raise OSError(98,'HOST_PRIVATE_PORT')
        self.address = address
    def getsockname(self):return ('0.0.0.0',69) if self.action == 'binding' else self.address
    def sendmsg(self,buffers,ancillary,flags,target):
        if self.on_send:self.on_send()
        self.sent.append((b''.join(buffers),ancillary,flags,target))
        return 0 if self.action == 'short_send' else len(buffers[0])
    def recvmsg(self,length,ancillary_length,flags):
        self.received.append((length,ancillary_length,flags))
        if self.on_recv:return self.on_recv()
        if self.queue:return self.queue.pop(0)
        raise socket.timeout()
    queue = None


class Harness:
    def __init__(self, **changes):
        self.ctx = context(); self.raw = FakeSocket(); self.raw.queue = []; self.now = 1.0
        self.cancelled = False; self.current_proof = proof(self.ctx); self.owner = threading.RLock(); self.created = []
        self.creator = object()
        def factory(*arguments):self.created.append(arguments); return self.raw
        args = dict(context=self.ctx,proof_callback=lambda ctx,budget:self.current_proof,
                    cancelled=lambda:self.cancelled,ownership_lock=self.owner,clock=lambda:self.now,
                    socket_factory=factory,if_nametoindex=lambda name:9,xid=fixture.XID)
        args.update(changes); self.client = adapter.DhcpSocketClient(**args)
    def offer(self):
        self.now = 2.0; self.raw.queue.append(envelope()); return self.client.poll()
    def ack(self, lease=60):
        self.now = 5.0; self.raw.queue.append(envelope(packet(wire.ACK,lease=lease))); return self.client.poll()


class OpenTests(unittest.TestCase):
    def test_exact_udp68_device_numeric_pktinfo_broadcast_options_and_private_request(self):
        h = Harness(); h.client.open()
        self.assertEqual(h.created,[(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)])
        self.assertEqual(h.raw.address,('0.0.0.0',68)); self.assertFalse(h.raw.inheritable)
        self.assertEqual(h.raw.options[(socket.IPPROTO_IP,8)],1)
        self.assertEqual(h.raw.options[(socket.SOL_SOCKET,25)],b'mta1234abcd\0')
        request,ancillary,flags,target = h.raw.sent[0]
        self.assertEqual(target,('255.255.255.255',67)); self.assertEqual(flags,0)
        self.assertEqual(adapter.PKTINFO.unpack(ancillary[0][2]),(9,wire.ZERO,wire.ZERO))
        self.assertEqual(wire.decode(request)['type'],wire.DISCOVER); self.assertEqual(wire.decode(request)['flags'],0x8000)
        self.assertTrue(h.client.close())
    def test_invalid_context_stock_iface_bool_ids_and_huge_deadline_never_create_socket(self):
        bad = [context(ifname='wlan0'),context(ifname='lo'),context(ifindex=True),context(phy=True),context(wdev=0),
               context(task_epoch=False),context(receipt_id='PRIVATE'),context(boot_id='PRIVATE'),context(deadline=10**1000)]
        for ctx in bad:
            with self.subTest(ctx=ctx), mock.patch.object(socket,'socket',side_effect=AssertionError('no actual socket')):
                with self.assertRaises(adapter.DhcpSocketClientError):Harness(context=ctx)
    def test_requires_actual_common_rlock_and_valid_callbacks(self):
        for changes in (dict(ownership_lock=threading.Lock()),dict(proof_callback=None),dict(cancelled=True)):
            with self.assertRaises(adapter.DhcpSocketClientError):Harness(**changes)
    def test_wrong_epoch_identity_type_proof_or_missing_receipt_blocks_all_socket_creation(self):
        for change in (None,dict(context=context()),dict(native_epoch=3),dict(phy=True),dict(wdev=8),dict(ifindex=8),
                dict(ifname='wlan0'),dict(iftype=9),dict(receipt_fsynced=False),dict(persistent_readback_verified=False),
                dict(ipv4_unconfigured=False),dict(association_verified=1)):
            h = Harness(); h.current_proof = True if change is None else proof(h.ctx,**change)
            with self.assertRaises(adapter.DhcpSocketClientError):h.client.open()
            self.assertFalse(h.created); self.assertTrue(h.client.close())
    def test_socket_options_conflict_and_short_send_failure_no_fallback_or_factory_retry(self):
        for action in ('device','pktinfo','broadcast','reuse','inherit','binding','timeout','port_conflict','short_send'):
            with self.subTest(action=action):
                h = Harness(); h.raw.action = action
                with self.assertRaises(adapter.DhcpSocketClientError):h.client.open()
                self.assertEqual(len(h.created),1); self.assertTrue(h.client.close())
                self.assertEqual(h.raw.fd,-1)
    def test_factory_exception_resources_unknown_are_never_cleared_by_fd_or_close(self):
        h = Harness(socket_factory=mock.Mock(side_effect=OSError('HOST_PRIVATE_FACTORY')))
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.open()
        self.assertFalse(h.client.close()); self.assertTrue(h.client.status()['factory_resources_unknown'])
        self.assertFalse(h.client.status()['socket_close_verified'])
    def test_close_failure_keeps_exact_reference_until_later_owner_close_verifies(self):
        h = Harness(); h.client.open(); h.raw.action = 'close_fail'
        self.assertFalse(h.client.close()); self.assertTrue(h.client.status()['socket_actor_pending'])
        h.raw.action = None; self.assertTrue(h.client.close()); self.assertEqual(h.raw.fd,-1)
    def test_closed_capsule_never_reopens(self):
        h = Harness(); self.assertTrue(h.client.close())
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.open()
        self.assertFalse(h.created)
    def test_linux_api_absence_and_boolean_socket_family_fail_without_fallback(self):
        h = Harness()
        with mock.patch.object(socket,'CMSG_SPACE',None):
            with self.assertRaisesRegex(adapter.DhcpSocketClientError,'invalid_socket_api'):h.client.open()
        self.assertFalse(h.created); self.assertTrue(h.client.close())
        h = Harness(); h.raw.family = True
        with self.assertRaisesRegex(adapter.DhcpSocketClientError,'invalid_socket_api'):h.client.open()
        self.assertEqual(len(h.created),1); self.assertFalse(h.raw.sent); self.assertTrue(h.client.close())
    def test_factory_non_socket_return_retains_unknown_ownership_not_just_fd_state(self):
        h = Harness(socket_factory=lambda *unused:None)
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.open()
        self.assertFalse(h.client.close()); self.assertTrue(h.client.status()['factory_resources_unknown'])
    def test_proof_budget_exception_and_nonfinite_clock_are_fail_closed_before_factory(self):
        for mode in ('budget','exception','huge','nan','infinity'):
            h = Harness()
            def provider(ctx,budget):
                if mode == 'exception':raise OSError('HOST_PRIVATE_PROOF')
                h.now = {'budget':2.0,'huge':10**1000,'nan':float('nan'),'infinity':float('inf')}[mode]
                return proof(ctx)
            h.client._proof_callback = provider
            with self.assertRaises(adapter.DhcpSocketClientError) as error:h.client.open()
            self.assertNotIn('HOST_PRIVATE',str(error.exception)); self.assertFalse(h.created)
            self.assertTrue(h.client.close())
    def test_invalid_cancel_callback_is_not_boolean_authorization(self):
        for value in (None,1,'false'):
            h = Harness(cancelled=lambda:value)
            with self.assertRaisesRegex(adapter.DhcpSocketClientError,'cancel_invalid'):h.client.open()
            self.assertFalse(h.created); self.assertTrue(h.client.close())


class DoraTests(unittest.TestCase):
    def test_dynamic_server_not_dot1_offer_ack_private_candidate_no_installed_endpoint(self):
        h = Harness(); h.client.open(); h.offer(); h.ack()
        value = h.client.candidate(); self.assertEqual(value.allocation.server_ip,fixture.SERVER)
        self.assertEqual(value.allocation.local_ip,fixture.CLIENT); self.assertEqual(value.allocation.usable_until,62.0)
        self.assertFalse(value.interface_configured); self.assertFalse(value.endpoint_verified)
        self.assertEqual(wire.decode(h.raw.sent[1][0])['options'][54],wire.ipv4(fixture.SERVER))
        self.assertTrue(h.client.close())
    def test_source_option54_consistency_is_not_endpoint_authentication(self):
        h = Harness(); h.client.open()
        h.raw.queue.append(envelope(source=('10.70.4.10',67)))
        self.assertEqual(h.client.poll(),{'event':'ignored','reason':'server_identity_mismatch'})
        self.assertIsNone(h.client.candidate()); self.assertEqual(len(h.raw.sent),1)
        h.client.close()
    def test_ingress_wrong_ports_iface_destination_specdst_ancillary_or_truncated_rejected(self):
        malformed = [envelope(source=(fixture.SERVER,68)),envelope(source=('8.8.8.8',67)),envelope(index=1),
            envelope(local=wire.ipv4(fixture.SERVER)),envelope(destination=wire.ipv4(fixture.CLIENT)),
            envelope(flags=0x20),envelope(flags=0x8),envelope(flags=True),envelope(ancillary=[]),
            envelope(ancillary=[(socket.IPPROTO_IP,8,b'INVALID')]),envelope(payload=b'X'*1473)]
        for item in malformed:
            h = Harness(); h.client.open(); h.raw.queue.append(item)
            self.assertEqual(h.client.poll()['event'],'ignored'); self.assertEqual(len(h.raw.sent),1)
            self.assertIsNone(h.client.candidate()); h.client.close()
    def test_duplicate_unknown_and_bool_ancillary_types_rejected(self):
        correct = envelope()[1][0]
        for ancillary in ([correct,correct],[(1,9,correct[2])],[(True,8,correct[2])],[(1,True,correct[2])]):
            h = Harness(); h.client.open(); h.raw.queue.append(envelope(ancillary=ancillary))
            self.assertEqual(h.client.poll()['reason'],'pktinfo_invalid'); h.client.close()
    def test_request_retransmission_does_not_extend_initial_request_lease(self):
        h = Harness(); h.client.open(); h.offer(); h.now = 3.0; h.client.poll(); h.now = 4.0; h.client.poll()
        h.ack(lease=10); self.assertEqual(h.client.candidate().allocation.usable_until,12.0)
        h.now = 12.0; self.assertIsNone(h.client.candidate()); h.client.close()
    def test_ack_server_address_mask_xid_mac_drift_never_commits_candidate(self):
        for changes in (dict(server='10.70.4.10'),dict(client='10.70.4.32'),dict(mask='255.255.0.0'),dict(xid=1),dict(mac=fixture.OTHER_MAC)):
            h = Harness(); h.client.open(); h.offer(); h.raw.queue.append(envelope(packet(wire.ACK,**changes)))
            self.assertEqual(h.client.poll()['event'],'ignored'); self.assertIsNone(h.client.candidate()); h.client.close()
    def test_nak_cancel_and_expiry_never_install_or_return_live_configuration(self):
        h = Harness(); h.client.open(); h.offer(); h.raw.queue.append(envelope(packet(wire.NAK)))
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.poll()
        self.assertTrue(h.client.close())
        for mode in ('cancel','deadline','backwards'):
            h = Harness(); h.client.open(); h.offer(); h.ack()
            if mode == 'cancel':h.cancelled = True
            elif mode == 'deadline':h.now = 100
            else:h.now = 1
            with self.assertRaises(adapter.DhcpSocketClientError):h.client.candidate()
            self.assertTrue(h.client.close())
    def test_received_packet_count_budget_does_not_open_new_transaction(self):
        h = Harness(); h.client.open(); h.raw.queue.extend([envelope(payload=b'X'*240)]*65)
        for unused in range(64):self.assertEqual(h.client.poll()['event'],'ignored')
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.poll()
        self.assertEqual(len(h.created),1); self.assertEqual(len(h.raw.sent),1); self.assertTrue(h.client.close())
    def test_proof_lost_after_offer_before_request_transmission_never_sends(self):
        h = Harness(); h.client.open(); calls = []
        def change_proof(ctx,budget):
            calls.append(True)
            return proof(ctx,association_verified=len(calls)<3)
        h.client._proof_callback = change_proof
        h.raw.queue.append(envelope())
        with self.assertRaises(adapter.DhcpSocketClientError):h.client.poll()
        self.assertEqual(len(h.raw.sent),1); self.assertTrue(h.client.close())
    def test_recv_length_and_ancillary_budget_are_explicit(self):
        h = Harness(); h.client.open(); h.client.poll()
        self.assertEqual(h.raw.received,[(wire.MAX_PACKET+1,socket.CMSG_SPACE(adapter.PKTINFO.size),0)])
        h.client.close()


class RaceTests(unittest.TestCase):
    def prepare_worker(self, h, callback):
        errors = []
        def target():
            try:callback()
            except adapter.DhcpSocketClientError as error:errors.append(str(error))
        thread = threading.Thread(target=target)
        ticket = h.client.reserve_runner(thread,h.creator)
        return thread,errors,ticket
    def worker(self, h, callback):
        thread,errors,ticket = self.prepare_worker(h,callback); thread.start(); return thread,errors,ticket
    def release_ticket(self, h, ticket):
        self.assertFalse(h.client.close())
        def completed(client,ctx,record,creator,generation,budget):
            return adapter.RunnerClosedProof(client,ctx,record,creator,generation,True)
        self.assertTrue(h.client.confirm_runner_closed(ticket,h.creator,completed))
        self.assertTrue(h.client.close())
    def test_late_factory_returns_socket_after_close_keeps_opening_actor_until_exit(self):
        entered = threading.Event(); release = threading.Event(); h = Harness()
        def factory(*unused):entered.set(); release.wait(2); return h.raw
        h.client._factory = factory
        thread,errors,ticket = self.worker(h,h.client.open); self.assertTrue(entered.wait(1))
        self.assertFalse(h.client.close()); self.assertFalse(h.client.status()['socket_close_verified'])
        release.set(); thread.join(2); self.assertFalse(thread.is_alive()); self.assertTrue(errors)
        self.assertEqual(h.raw.fd,-1); self.assertFalse(h.raw.sent); self.release_ticket(h,ticket)
    def test_blocked_proof_is_pending_and_never_starts_factory_after_cancel(self):
        entered = threading.Event(); release = threading.Event(); h = Harness()
        def provider(ctx,budget):entered.set(); release.wait(2); return proof(ctx)
        h.client._proof_callback = provider
        thread,errors,ticket = self.worker(h,h.client.open); self.assertTrue(entered.wait(1))
        self.assertFalse(h.client.close()); release.set(); thread.join(2)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors); self.assertFalse(h.created); self.release_ticket(h,ticket)
    def test_fd_minus1_does_not_prove_inflight_recv_actor_exited(self):
        entered = threading.Event(); release = threading.Event(); h = Harness()
        def receive():entered.set(); release.wait(2); return envelope()
        h.raw.on_recv = receive
        thread,errors,ticket = self.prepare_worker(h,h.client.poll)
        h.client.open(); thread.start(); self.assertTrue(entered.wait(1))
        self.assertFalse(h.client.close()); self.assertEqual(h.raw.fd,-1)
        self.assertTrue(h.client.status()['socket_actor_pending']); release.set(); thread.join(2)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors); self.assertEqual(len(h.raw.sent),1)
        self.release_ticket(h,ticket)
    def test_inflight_send_cannot_late_publish_candidate_after_close(self):
        entered = threading.Event(); release = threading.Event(); h = Harness()
        def sending():entered.set(); release.wait(2)
        h.raw.on_send = sending
        thread,errors,ticket = self.worker(h,h.client.open); self.assertTrue(entered.wait(1))
        self.assertFalse(h.client.close()); release.set(); thread.join(2)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors); self.release_ticket(h,ticket)
        self.assertFalse(h.client.status()['endpoint_verified'])
    def test_common_owner_lock_timeout_never_opens_or_sends_socket(self):
        h = Harness(); entered = threading.Event(); release = threading.Event()
        def holder():
            with h.owner:entered.set(); release.wait(2)
        thread = threading.Thread(target=holder); thread.start(); self.assertTrue(entered.wait(1))
        try:
            with self.assertRaisesRegex(adapter.DhcpSocketClientError,'lock_timeout'):h.client.open()
            self.assertFalse(h.created); self.assertFalse(h.raw.sent); self.assertTrue(h.client.close())
        finally:release.set(); thread.join(2)
        self.assertFalse(thread.is_alive())


class RunnerTests(unittest.TestCase):
    def test_unregistered_nonmain_open_poll_candidate_cannot_create_io_or_call_proof(self):
        for method in ('open','poll','candidate'):
            h = Harness(); errors = []; calls = []
            if method != 'open':h.client.open()
            h.client._proof_callback = lambda ctx,budget:calls.append(True) or proof(ctx)
            transmitted = len(h.raw.sent); received = len(h.raw.received); factories = len(h.created)
            def target():
                try:getattr(h.client,method)()
                except adapter.DhcpSocketClientError as error:errors.append(str(error))
            thread = threading.Thread(target=target); thread.start(); thread.join(2)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors,['invalid_runner']); self.assertFalse(calls)
            self.assertEqual(len(h.raw.sent),transmitted); self.assertEqual(len(h.raw.received),received)
            self.assertEqual(len(h.created),factories); self.assertTrue(h.client.close())
    def test_direct_method_return_does_not_release_live_thread_or_ticket_before_exact_proof(self):
        for method in ('open','poll','candidate'):
            h = Harness(); returned = threading.Event(); release = threading.Event(); errors = []
            def target():
                try:getattr(h.client,method)()
                except adapter.DhcpSocketClientError as error:errors.append(str(error))
                finally:returned.set(); release.wait(2)
            thread = threading.Thread(target=target); ticket = h.client.reserve_runner(thread,h.creator)
            if method != 'open':h.client.open()
            thread.start(); self.assertTrue(returned.wait(1)); self.assertFalse(errors)
            self.assertTrue(thread.is_alive()); self.assertFalse(h.client.close())
            self.assertEqual(h.raw.fd,-1); self.assertTrue(h.client.status()['runner_producer_pending'])
            def completed(client,ctx,record,creator,generation,budget):
                return adapter.RunnerClosedProof(client,ctx,record,creator,generation,True)
            self.assertFalse(h.client.confirm_runner_closed(ticket,h.creator,completed))
            release.set(); thread.join(2); self.assertFalse(thread.is_alive())
            self.assertFalse(h.client.close()); self.assertFalse(h.client.confirm_runner_closed(ticket,h.creator,lambda *unused:True))
            self.assertTrue(h.client.confirm_runner_closed(ticket,h.creator,completed)); self.assertTrue(h.client.close())
    def test_reserved_but_not_started_thread_remains_pending_until_exact_owner_proof(self):
        h = Harness(); thread = threading.Thread(target=lambda:None); ticket = h.client.reserve_runner(thread,h.creator)
        self.assertFalse(h.client.close())
        self.assertFalse(h.client.confirm_runner_closed(ticket,h.creator,lambda *unused:True))
        def completed(client,ctx,record,creator,generation,budget):return adapter.RunnerClosedProof(client,ctx,record,creator,generation,True)
        self.assertTrue(h.client.confirm_runner_closed(ticket,h.creator,completed)); self.assertTrue(h.client.close())
    def test_runner_return_is_not_thread_exit_and_wrong_closure_identity_cannot_release(self):
        h = Harness(); h.raw.queue.extend([envelope(),envelope(packet(wire.ACK))]); returned = threading.Event(); exit_thread = threading.Event(); data = []
        ticket = None
        def target():data.append(h.client.run(ticket)); returned.set(); exit_thread.wait(2)
        thread = threading.Thread(target=target); ticket = h.client.reserve_runner(thread,h.creator); thread.start()
        self.assertTrue(returned.wait(1)); self.assertFalse(h.client.close())
        def completed(client,ctx,record,creator,generation,budget):return adapter.RunnerClosedProof(client,ctx,record,creator,generation,True)
        self.assertFalse(h.client.confirm_runner_closed(ticket,h.creator,completed))
        exit_thread.set(); thread.join(2); self.assertFalse(thread.is_alive())
        for bad in (lambda *args:True,lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(client,context(),record,creator,generation,True),
                lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(client,ctx,record,creator,generation-1,True),
                lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(object(),ctx,record,creator,generation,True),
                lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(client,ctx,record._replace(generation=0),creator,generation,True),
                lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(client,ctx,record,object(),generation,True),
                lambda client,ctx,record,creator,generation,budget:adapter.RunnerClosedProof(client,ctx,record,creator,generation,1)):
            self.assertFalse(h.client.confirm_runner_closed(ticket,h.creator,bad))
        self.assertFalse(h.client.confirm_runner_closed(None,h.creator,completed))
        self.assertFalse(h.client.confirm_runner_closed(ticket,object(),completed))
        self.assertTrue(h.client.confirm_runner_closed(ticket,h.creator,completed)); self.assertTrue(h.client.close())
        self.assertFalse(data[0].endpoint_verified); self.assertFalse(data[0].interface_configured)


class SourceTests(unittest.TestCase):
    def test_frozen_core_sha_python35_no_assert_and_no_network_mutation_helpers(self):
        self.assertEqual(hashlib.sha256((PROJECT/'runtime/mta_dhcp_client_core.py').read_bytes()).hexdigest(),
                         '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa')
        tree = ast.parse((PROJECT/'runtime/mta_dhcp_client.py').read_text(encoding='utf-8'),feature_version=(3,5))
        self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        source = (PROJECT/'runtime/mta_dhcp_client.py').read_text(encoding='utf-8')
        for token in ('subprocess','os.system','SOCK_RAW','killall','netlink','send_available\":True'):
            self.assertNotIn(token,source)
        self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and
                             isinstance(node.func.value,ast.Name) and node.func.value.id == 'threading' and
                             node.func.attr == 'Thread' for node in ast.walk(tree)))
    def test_public_status_contains_no_private_identity_configuration_or_ports(self):
        h = Harness(); h.client.open(); h.offer(); h.ack(); text = json.dumps(h.client.status())
        for secret in (fixture.SERVER,fixture.CLIENT,h.ctx.ifname,h.ctx.boot_id,h.ctx.receipt_id,'HOST_PRIVATE','endpoint_port'):
            self.assertNotIn(secret,text)
        for flag in ('endpoint_verified','interface_configured','send_available','receive_available'):self.assertFalse(h.client.status()[flag])
        h.client.close()


if __name__ == '__main__':unittest.main()
