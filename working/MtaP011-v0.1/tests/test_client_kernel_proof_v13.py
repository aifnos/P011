"""New HOST-only methods: actual reader/codec over Fake OS, never real GET."""
import ast
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
import test_client_caps_transport as fixture
import test_client_proc as proc_fixture
import mta_client_proc as proc
import mta_p2p_client_init as core

PATH = BASE / 'candidate/client-kernel-proof-v13/runtime/mta_client_kernel_proof.py'
spec = importlib.util.spec_from_file_location('private_kernel_proof_v13', str(PATH))
k = importlib.util.module_from_spec(spec); spec.loader.exec_module(k)
BOOT = proc_fixture.BOOT
NAME = 'mta12345678'


def origin(): return core.Origin(0, 9, 7, NAME, 8)
def interface(role=8, frequency=2412, index=7):
    data = fixture.u32(1, 0) + fixture.u32(3, index) + fixture.attr(4, NAME.encode() + b'\0') + fixture.attr(153, struct.pack('<Q', 9))
    if role is not None: data += fixture.u32(5, role)
    if frequency is not None: data += fixture.u32(38, frequency)
    return data + fixture.u32(46, 1)


def station(mask=0xa2, values=0xa2, index=7, duplicate=False):
    attrs = fixture.attr(17, struct.pack('<II', mask, values)) if mask is not None else b''
    if duplicate: attrs += attrs
    return fixture.u32(3, index) + fixture.attr(6, b'\x02\x11\x22\x33\x44\x55') + fixture.u32(46, 2) + fixture.attr(21, attrs, 0x8000)


def packets(ifaces=None, stations=None):
    ifaces = [interface()] * 3 if ifaces is None else ifaces
    stations = [[station()], [station()]] if stations is None else stations
    data = [fixture.genl(16, 1, 1, fixture.family(), version=2)]
    for sequence, face in zip((2, 4, 6), ifaces):
        data.append(fixture.genl(23, sequence, 7, face))
        if sequence != 6:
            for value in stations[(sequence-2)//2]: data.append(fixture.genl(23, sequence+1, 19, value, flags=2))
            data.append(fixture.nl(3, sequence+1, struct.pack('<i', 0), flags=2))
    return data


class FakeSocket(fixture.FakeSocket):
    def __init__(self, io, values):
        super(FakeSocket, self).__init__(values); self.io = io
        self.timeout_nanosecond_quantized = True
    def close(self):
        original = self.fd
        super(FakeSocket, self).close()
        if self.fd == -1: self.io.live.pop(original, None)


class FakeIo(object):
    def __init__(self, values=None):
        self.live = {}; self.open_calls = []; self.close_calls = []; self.next = 20
        self.raw = FakeSocket(self, packets() if values is None else values)
        self.index_values = [b'7\n', b'7\n']; self.fail_file_close = False
        self.socket_factory_error = None
    def new_socket(self):
        if self.socket_factory_error: raise self.socket_factory_error
        self.live[17] = [None, b'', 0, stat.S_IFSOCK | 0o600]
        return self.raw
    def open_ifindex(self, name):
        if name != NAME: raise AssertionError('non-owned selector')
        self.next += 1; self.open_calls.append(name)
        self.live[self.next] = [name, self.index_values[len(self.open_calls)-1], 0, stat.S_IFREG | 0o444]
        return self.next
    def fstat(self, fd):
        if fd not in self.live: raise OSError(errno.EBADF, 'Fake closed')
        return types.SimpleNamespace(st_dev=1, st_ino=fd+100, st_mode=self.live[fd][3], st_uid=0, st_gid=0)
    def read(self, fd, count):
        name, data, at, mode = self.live[fd]; value = data[at:at+count]
        self.live[fd][2] += len(value); return value
    def close(self, fd):
        self.close_calls.append(fd)
        if self.fail_file_close: raise OSError(errno.EIO, 'Fake ambiguous close')
        del self.live[fd]


class KernelProofTests(unittest.TestCase):
    def setUp(self):
        for name in ('open', 'read', 'close', 'fstat', 'kill', 'waitpid'):
            patch = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch('socket.socket', side_effect=AssertionError('actual socket forbidden'))
        patch.start(); self.addCleanup(patch.stop)
    def reader(self, io=None, proc_change=None, clock=None):
        io = io or FakeIo(); readers = []
        def factory(timeout, _clock):
            fs = proc_fixture.FakeFs()
            if proc_change is not None: proc_change(fs, len(readers))
            r = proc.ProcReader(timeout=timeout, _clock=_clock, _fs=fs); readers.append(r); return r
        owner, epoch = object(), 100000001
        value = k.ClientKernelReader(origin(), BOOT, owner, epoch, _io=io,
            _proc_factory=factory, _clock=clock or (lambda: 100.0))
        return value, io, readers, owner, epoch
    def reject(self, io=None, code=None, **kwargs):
        r, io, readers, owner, epoch = self.reader(io, **kwargs)
        with self.assertRaises(k.KernelReadError) as error: r.read()
        if code is not None: self.assertEqual(error.exception.code, code)
        return r, io, readers
    def test_pure_ctor_and_python35_no_mutation_source(self):
        r = k.ClientKernelReader(origin(), BOOT, object(), 1)
        self.assertFalse(r.status()['attempted']); self.assertFalse(r.status()['resource_pending'])
        tree = ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        calls = [n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertFalse(set(calls) & {'kill', 'waitpid', 'mkdir', 'unlink', 'system', 'Popen', 'write', 'flock'})
    def test_operation_epoch_strict_bounded_value_binding(self):
        for epoch in (None, object(), True, False, 0, -1, 2**53+1, 1.0):
            with self.subTest(epoch_type=type(epoch).__name__):
                with self.assertRaises(k.KernelReadError): k.ClientKernelReader(origin(), BOOT, object(), epoch)
        r,io,readers,owner,epoch=self.reader(); result=r.read()
        equal_epoch=int(str(epoch)); self.assertEqual(equal_epoch,epoch)
        self.assertIsNone(r.authenticate(owner,equal_epoch,result))
        for changed in (True,epoch+1,2**53+1):
            with self.assertRaises(k.KernelReadError): r.authenticate(owner,changed,result)
    def test_complete_actual_reader_fake_kernel_and_exact_issuer(self):
        r, io, readers, owner, epoch = self.reader(); result = r.read()
        self.assertEqual(result.public_summary()['role'], 'CLIENT')
        self.assertEqual([result.public_summary()[key] for key in ('associated','authorized','authenticated')], ['TRUE']*3)
        self.assertIsNone(r.authenticate(owner, epoch, result))
        with self.assertRaises(k.KernelReadError): r.authenticate(object(), epoch, result)
        with self.assertRaises(AttributeError): result._channel = (9, 1)
        self.assertEqual(len(readers),2); self.assertEqual(len(r.raw_requests),6)
        self.assertEqual([b[16] for b in r.raw_requests], [3,5,17,5,17,5])
        self.assertTrue(r.status()['resources_closed']); self.assertFalse(io.live)
        self.assertTrue(all(row['closed'] for row in r.original_resources))
        self.assertEqual(io.raw.close_count,1)
        self.assertTrue(all(x._files==x._closed and not x._pending for x in readers))
        self.assertNotIn('2412', json.dumps(result.public_summary())); self.assertNotIn(NAME,repr(result))
        with self.assertRaises(k.KernelReadError): r.read()
        self.assertEqual(io.raw.close_count,1)
    def test_missing_frequency_or_flag_mask_remains_unknown(self):
        for faces, peers in (([interface(frequency=None)]*3, [[station(mask=None)]]*2),
                              ([interface(role=None)]*3, [[station(mask=2, values=2)]]*2)):
            with self.subTest():
                r,io,readers,owner,epoch=self.reader(FakeIo(packets(faces, peers))); result=r.read()
                self.assertEqual(result.public_summary()['associated'],'UNKNOWN')
                self.assertTrue(r.status()['resources_closed'])
    def test_empty_station_dump_is_unknown_not_disconnected(self):
        r,io,_,_,_=self.reader(FakeIo(packets(stations=[[],[]]))); result=r.read()
        self.assertEqual(result.public_summary()['associated'],'UNKNOWN')
        self.assertEqual(result.public_summary()['reason'],'no_station')
    def test_unsupported_station_is_unknown_and_post_interface_still_read(self):
        values=packets(stations=[[],[]]); selectors=k.wire._attr(3,struct.pack('<I',7))+k.wire._attr(153,struct.pack('<Q',9))
        for sequence, at in ((3,2),(5,4)):
            req=k._NL.pack(20+len(selectors),23,0x301,sequence,41)+k._GENL.pack(17,1,0)+selectors
            values[at]=fixture.nl(2,sequence,struct.pack('<i',-95)+req)
        r,io,_,_,_=self.reader(FakeIo(values)); result=r.read()
        self.assertEqual(result.public_summary()['reason'],'station_unsupported')
        self.assertEqual(result.public_summary()['associated'],'UNKNOWN')
        self.assertEqual(len(r.raw_requests),6)
    def test_interface_role_mismatch_is_reported_not_client(self):
        r,io,_,_,_=self.reader(FakeIo(packets(ifaces=[interface(role=9)]*3))); result=r.read()
        self.assertEqual(result.public_summary()['role'],'MISMATCH')
        self.assertFalse(result.public_summary()['production_available'])
    def test_interface_origin_index_and_channel_change_reject(self):
        for faces, code in (([interface(index=8)]*3,'interface_identity'),
                            ([interface(),interface(frequency=2437),interface()],'channel_changed')):
            with self.subTest():
                r,io,_=self.reject(FakeIo(packets(ifaces=faces)),code)
                self.assertTrue(r.status()['resources_closed']); self.assertFalse(io.live)
    def test_station_change_duplicate_flags_and_wrong_index_reject(self):
        cases=[([[station()],[station(values=2)]],'station_changed'),
               ([[station(duplicate=True)]]*2,'attribute_duplicate'),
               ([[station(index=8)]]*2,'station_identity'),
               ([[station(),station()]]*2,'station_identity')]
        for peers,code in cases:
            with self.subTest(): self.reject(FakeIo(packets(stations=peers)),code)
    def test_boot_or_executor_identity_change_reject_no_event_fallback(self):
        def boot(fs,index):
            if index: fs.files[proc_fixture.BOOT_PATH]=b'ffffffff-ffff-ffff-ffff-ffffffffffff\n'
        self.reject(proc_change=boot,code='process_unknown')
        def exe(fs,index):
            if index: fs.links['/proc/42/exe']='/private/different'
        self.reject(proc_change=exe,code='process_unknown')
    def test_sysfs_index_changed_reject_and_originals_closed(self):
        io=FakeIo();io.index_values[1]=b'8\n';r,io,_=self.reject(io,'ifindex_changed')
        self.assertTrue(r.status()['resources_closed']);self.assertFalse(io.live)
    def test_kernel_peer_seq_dump_flags_truncation_reject(self):
        for edit in ('peer','seq','flags','truncate'):
            with self.subTest(edit=edit):
                values=packets()
                if edit=='peer': values[0]=(values[0],[],0,(False,0))
                elif edit=='seq': values[0]=fixture.genl(16,8,1,fixture.family(),version=2)
                elif edit=='flags': values[3]=fixture.nl(3,3,struct.pack('<i',0),flags=16)
                else: values[0]=(values[0],[],32,(0,0))
                r,io,_=self.reject(FakeIo(values));self.assertTrue(r.status()['resources_closed'])
    def test_ancillary_unknown_retained_not_complete(self):
        values=packets();values[0]=(values[0],[(1,1,b'unknown')],0,(0,0))
        r,io,_=self.reject(FakeIo(values),'receive_unknown')
        self.assertTrue(r.status()['resource_pending']);self.assertEqual(io.raw.close_count,1)
    def test_close_failure_sticky_no_reclose_and_other_originals_attempted(self):
        io=FakeIo();io.raw.close_error=OSError(errno.EIO,'Fake close');r,io,_=self.reject(io,'resource_unknown')
        self.assertTrue(r.status()['resource_pending']);self.assertIs(r.original_resources[1]['value'],io.raw)
        with self.assertRaises(k.KernelReadError):r.read()
        self.assertEqual(io.raw.close_count,1);self.assertEqual(len(io.close_calls),2)
    def test_constructor_or_socket_creation_exception_strong_refs(self):
        io=FakeIo();io.socket_factory_error=RuntimeError('private unknown creator')
        r,io,_=self.reject(io,'read_failed');self.assertTrue(r.status()['resource_pending'])
        self.assertEqual(r.original_resources[-1]['kind'],'socket');self.assertTrue(r.original_resources[-1]['unknown'])
    def test_regressed_clock_deadline_and_interrupt_retained(self):
        values=iter([100.0,99.0]);r,io,_=self.reject(clock=lambda:next(values))
        self.assertEqual(io.open_calls,[])
        io=FakeIo();io.raw.recv_error=KeyboardInterrupt()
        r,io,_=self.reject(io,'interrupted');self.assertTrue(r.status()['resources_closed'])
    def test_repeated_empty_sta_info_padding_preserved_only_in_station_info(self):
        pad=fixture.attr(33,b'')
        info=pad+fixture.attr(23,struct.pack('<Q',1))+pad+fixture.attr(24,struct.pack('<Q',2))+pad+fixture.attr(17,struct.pack('<II',0xa2,0xa2))+pad
        encoded=fixture.attr(21,info,0x8000)
        peer=b''.join(row[3] for row in k.wire._attrs(station()) if row[0]!=21)+encoded
        r,io,_,owner,epoch=self.reader(FakeIo(packets(stations=[[peer],[peer]]))); result=r.read()
        self.assertEqual(result.public_summary()['associated'],'TRUE')
        self.assertIn(encoded,r.unassessed_attributes)
        self.assertTrue(any(encoded in row.data for row in r.raw_datagrams))
        self.assertIsNone(r.authenticate(owner,epoch,result));self.assertTrue(r.status()['resources_closed'])
        faces=[interface()+pad+pad]*3
        self.reject(FakeIo(packets(ifaces=faces)),'attribute_duplicate')
        ast.parse(PATH.read_text(encoding='utf-8'),feature_version=(3,5))
    def test_sta_info_nonempty_flagged_padding_and_other_duplicates_rejected(self):
        valid=fixture.attr(17,struct.pack('<II',0xa2,0xa2))
        for extra,code in ((fixture.attr(33,b'\0'),'attribute_format'),
                (fixture.attr(33,b'',0x8000),'attribute_format'),
                (fixture.attr(33,b'',0x4000),'attribute_format'),
                (fixture.attr(23,struct.pack('<Q',1))*2,'attribute_duplicate'),
                (valid,'attribute_duplicate')):
            with self.subTest(code=code):
                peer=b''.join(row[3] for row in k.wire._attrs(station()) if row[0]!=21)+fixture.attr(21,valid+extra,0x8000)
                r,io,_=self.reject(FakeIo(packets(stations=[[peer],[peer]])),code)
                self.assertTrue(r.status()['resources_closed']);self.assertFalse(io.live)
    def test_outer_deadline_after_final_real_self_observation(self):
        for final_time,accepted in ((104.999,True),(105.0,False),(105.001,False)):
            with self.subTest(final_time=final_time):
                now=[100.0];io=FakeIo();readers=[]
                def factory(timeout,_clock):
                    reader=proc.ProcReader(timeout=timeout,_clock=_clock,_fs=proc_fixture.FakeFs())
                    read_self=reader.read_self;last=len(readers)==1
                    def read_then_advance():
                        observation=read_self()
                        if last:now[0]=final_time
                        return observation
                    reader.read_self=read_then_advance;readers.append(reader);return reader
                owner=object();r=k.ClientKernelReader(origin(),BOOT,owner,1,_io=io,_proc_factory=factory,_clock=lambda:now[0])
                if accepted:
                    result=r.read();self.assertIsNone(r.authenticate(owner,1,result))
                else:
                    with self.assertRaises(k.KernelReadError) as error:r.read()
                    self.assertEqual(error.exception.code,'deadline')
                    self.assertIsNone(r._observation);self.assertFalse(r.status()['read_success'])
                self.assertEqual(len(readers),2);self.assertTrue(r.status()['resources_closed'])
                self.assertFalse(io.live);self.assertEqual(io.raw.close_count,1)


if __name__=='__main__':unittest.main()
