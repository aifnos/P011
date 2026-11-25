# -*- coding: utf-8 -*-
"""One new HOST87 method / 13 affected private packet and entry domains.

Actual frozen packet87 and entry87-r2 complete definitions execute. Actual
p011_json/ip/core/SnapshotData definitions validate one complete primitive
Snapshot DATA fixture; no native Snapshot/Actor/owner constructor is used.
The wire-capacity domain uses malformed primitive framing to test exact
length acceptance/rejection and complete retention, NOT a claim that a real
128 KiB device inventory fits or that malformed DATA is admitted.

Entry filesystem, FD1/FIFO/access/PC_PIPE_BUF, select/write/EBADF, PID and
clock are explicit POSIX HOST models. POSIX constants are a module-local
projection, not Windows/Linux kernel evidence. No real pipe/process/helper,
collect(), Loader38 load, State, Server, Parent, RF, restore or admission runs.
No old TestCase/helper/test method is imported or replayed. Default-main,
source-read, packet-writer and close paths are the actual new algorithms.
"""
import builtins
import errno
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ('host/go_readonly_observer_v85_definition_manifest.json', 8983,
            'e6098e979b7f311defdea64f6934f38857488a930ca6337b091f12852a41dc78')
PACKET_SOURCE = ('candidate/go-send-observer-entry-v87/runtime/mta_observer_packet.py', 13223,
                 '6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a')
ENTRY_SOURCE = ('candidate/go-send-observer-entry-v87-r2/runtime/mta_go_readonly_entry.py', 25537,
                '41ec9d93147b875bb38363f15e545962459e4eaba161ccc5fb7759ce6c5c7df9')
MARKER = ('HOST87_ENTRY new_methods=1 old_methods=0 cases=13 '
          'filesystem_model=true pipe_model=true device=false phone=false\n')
PHYSICAL = '/var/volatile/tmp/p011-mta-go-observer-v85'
ALIAS = '/tmp/p011-mta-go-observer-v85'


def _fixed(item):
    path, size, pin = item
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('HOST87 fixed source input changed')
    return raw


def _sources():
    value = json.loads(_fixed(MANIFEST).decode('ascii'))
    if (type(value) is not dict or set(value) != {'schema', 'sources'} or
            value['schema'] != 'go-readonly-observer-v85-definitions' or
            type(value['sources']) is not list or len(value['sources']) != 39):
        raise AssertionError('HOST87 fixed definition manifest')
    result = {}
    for row in value['sources']:
        if type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'}:
            raise AssertionError('HOST87 fixed definition row')
        result[row['module']] = _fixed((row['path'], row['bytes'], row['sha256']))
    if len(result) != 39:
        raise AssertionError('HOST87 duplicate definition')
    return result, _fixed(PACKET_SOURCE), _fixed(ENTRY_SOURCE)


class _Definitions(object):
    """Source-only inputs; execute only four pure defs and the two new defs."""
    def __init__(self, case, sources, packet_raw, entry_raw):
        self.case, self.modules = case, {}
        self.names = ('p011_json', 'mta_ip', 'mta_p2p_client_init', 'mta_snapshot_data',
                      'mta_observer_packet', 'mta_go_readonly_entry')
        self.before = dict((name, sys.modules.get(name)) for name in self.names)
        case.assertTrue(all(value is None for value in self.before.values()))
        original_import = builtins.__import__

        def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in self.names:
                if name not in self.modules or sys.modules.get(name) is not self.modules[name]:
                    raise AssertionError('HOST87 fixed import order')
                return self.modules[name]
            if level or name.startswith(('mta_', 'p011_')):
                raise AssertionError('HOST87 no source fallback')
            return original_import(name, globals, locals, fromlist, level)

        try:
            for name in self.names:
                raw = packet_raw if name == 'mta_observer_packet' else (
                    entry_raw if name == 'mta_go_readonly_entry' else sources[name])
                module = types.ModuleType(name)
                module.__file__ = PHYSICAL + '/runtime/' + name + '.py'
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
                self.modules[name] = module
                sys.modules[name] = module
                exec(compile(raw, module.__file__, 'exec'), module.__dict__)
            self.packet = self.modules['mta_observer_packet']
            self.entry = self.modules['mta_go_readonly_entry']
            self.snapshots = self.modules['mta_snapshot_data']
            # Local explicit POSIX flag DATA; never changes the global os module.
            self.entry.os = types.SimpleNamespace(O_ACCMODE=3, O_WRONLY=1, O_NONBLOCK=0x800)
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in reversed(self.names):
            original = self.modules.get(name)
            if original is not None and sys.modules.get(name) is original:
                del sys.modules[name]
        for name, value in self.before.items():
            self.case.assertIs(sys.modules.get(name), value)

    def result(self):
        codec = self.snapshots
        station = (0, 1, 2, 'wlan0', 2)
        actors = tuple((pid, pid + 100, exe, 'a' * 64, ((pid, pid + 100, 'S'),))
            for pid, exe in ((1, '/usr/bin/Z03'), (2, '/usr/bin/control_engine'), (3, '/usr/bin/weston')))
        fields = ('11111111-2222-3333-4444-555555555555', tuple(sorted(codec._STOCK_PINS)),
            actors, station, 'b' * 64, 2412, (station,),
            ((), (), ((0, 255), (32766, 254), (32767, 253))), (), (), True)
        # Primitive fixture DATA only. Do not construct core Snapshot/Actor/IP records.
        codec._full(fields)
        key = codec._stable_key(fields)
        raw = codec._canonical([codec.DATA_SCHEMA, codec._pack(fields), codec._pack(key)])
        decoded = codec.decode_snapshot(raw)
        binding = _binding()
        return dict(schema='p011-go-preflight-data-v85', binding=tuple(sorted(binding.items())),
            snapshot_raw=raw, stable_key_sha256=decoded.key_sha,
            helper_raw=tuple((path, b'{"event":"capabilities"}\n', b'') for path, pin in self.packet.HELPERS),
            lock_metadata=(1, 2, 0o100600, 0, 0, 1, 0, 10, 20),
            source_manifest_sha256=self.packet.SOURCE_MANIFEST_SHA, source_count=38,
            active_until=binding['until'], cleanup_until=binding['cleanup_until'],
            rf_requested=False, restoration_verified=False, production_admitted=False)


def _binding():
    return dict(nonce='a' * 32, task_id='b' * 32, native_epoch=1, operation_epoch=1,
                until=30.0, cleanup_until=35.0)


class _Clock(object):
    def __init__(self): self.value, self.calls = 1.0, 0
    def __call__(self):
        self.calls += 1
        return self.value


def _metadata(ino, mode, size=0, target=None):
    return types.SimpleNamespace(st_dev=87, st_ino=ino, st_mode=mode, st_uid=0, st_gid=0,
        st_nlink=2 if stat.S_ISDIR(mode) else 1, st_size=size if target is None else len(target),
        st_rdev=0, st_mtime_ns=1000000000 + ino, st_ctime_ns=2000000000 + ino)


class _PosixModel(object):
    """No actual filesystem/pipe. Exact FD identity, active IO and EBADF models."""
    def __init__(self, clock, loader_raw):
        self.clock, self.loader_raw = clock, loader_raw
        self.calls, self.live, self.close_counts, self.sent = [], {1: True}, {}, []
        self.flags_value, self.pipe_buf_value = 1, 4096
        self.output_meta = _metadata(901, stat.S_IFIFO | 0o600)
        self.source_meta = _metadata(902, stat.S_IFREG | 0o400, len(loader_raw))
        self.offset, self.next_fd = 0, 3
        self.late_fstat = self.late_read = self.backpressure = self.short_write = False
        self.eagain = None

    def validate(self): self.calls.append(('model_validate',))
    def pid(self):
        self.calls.append(('model_pid',))
        return 8701
    def stat(self, path):
        self.calls.append(('stat', path))
        if path == ALIAS or path.startswith(ALIAS + '/'):
            path = PHYSICAL + path[len(ALIAS):]
        if path.endswith('/mta_go_readonly_loader.py'):
            return self.source_meta
        dirs = {'/': (101, 0o755), '/var': (102, 0o755), '/var/volatile': (103, 0o1777),
                '/var/volatile/tmp': (104, 0o1777), PHYSICAL: (105, 0o700),
                PHYSICAL + '/runtime': (106, 0o700)}
        if path in dirs:
            ino, mode = dirs[path]
            return _metadata(ino, stat.S_IFDIR | mode)
        if path in ('/tmp', '/var/tmp'):
            target = '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
            return _metadata(107 if path == '/tmp' else 108, stat.S_IFLNK | 0o777, target=target)
        raise OSError(errno.ENOENT, 'HOST87 modeled absent path')
    def readlink(self, path):
        self.calls.append(('readlink', path))
        return '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
    def open(self, path):
        self.calls.append(('open', path))
        fd = self.next_fd
        self.next_fd += 1
        self.live[fd] = True
        return fd
    def fstat(self, fd):
        self.calls.append(('fstat', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST87 modeled closed original')
        value = self.output_meta if fd == 1 else self.source_meta
        if self.late_fstat:
            self.late_fstat = False
            self.clock.value = 30.0
        return value
    def read(self, fd, count):
        self.calls.append(('read', fd, count))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST87 modeled closed original')
        raw = self.loader_raw[self.offset:self.offset + count]
        self.offset += len(raw)
        if self.late_read: self.clock.value = 30.0
        return raw
    def close(self, fd):
        self.calls.append(('close', fd))
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST87 modeled duplicate close')
        del self.live[fd]
        return None
    def flags(self, fd):
        self.calls.append(('flags', fd))
        return self.flags_value
    def set_flags(self, fd, value):
        self.calls.append(('set_flags', fd, value))
        self.flags_value = value
        return 0
    def pipe_buf(self, fd):
        self.calls.append(('model_pipe_buf', fd))
        return self.pipe_buf_value
    def writable(self, fd, timeout):
        self.calls.append(('model_select', fd, timeout))
        if self.backpressure:
            self.clock.value = 30.0
            return []
        return [fd]
    def write(self, fd, raw):
        self.calls.append(('model_write', fd, len(raw)))
        if self.eagain is not None:
            error, self.eagain = self.eagain, None
            raise error
        returned = len(raw) - 1 if self.short_write else len(raw)
        self.sent.append(raw[:returned])
        return returned


class GoReadonlyEntry87Test(unittest.TestCase):
    def test_private_packet_and_entry_boundaries(self):
        sources, packet_raw, entry_raw = _sources()
        done = []
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST87 no process')) as process, \
                mock.patch('socket.socket', side_effect=AssertionError('HOST87 no socket/RF')) as socket, \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('HOST87 no native library')) as library, \
                mock.patch('os.mkdir', side_effect=AssertionError('HOST87 no directory')) as mkdir:
            wires = (process, socket, library, mkdir)
            domain = _Definitions(self, sources, packet_raw, entry_raw)
            try:
                packet, entry = domain.packet, domain.entry
                result = domain.result()
                raw = packet.encode_result(result)

                def writer():
                    clock = _Clock()
                    io = _PosixModel(clock, sources['mta_go_readonly_loader'])
                    value = entry.ReadonlyObserverEntry(_binding(), _io=io, _clock=clock)
                    self.assertEqual(io.calls, [])
                    self.assertEqual(clock.calls, 0)
                    return value, io, clock

                def close_output(value, io):
                    value._close(value.output, True)
                    if value.output['closed']:
                        self.assertEqual(io.close_counts[1], 1)
                        calls = tuple(io.calls)
                        value._close(value.output, True)
                        self.assertEqual(tuple(io.calls), calls)

                decoded = packet.decode_packet(raw)
                self.assertEqual(decoded.private_snapshot_ascii(), result['snapshot_raw'])
                self.assertEqual(decoded.snapshot.key_sha, result['stable_key_sha256'])
                self.assertEqual(decoded.helper_raw, result['helper_raw'])
                self.assertEqual(decoded.lock_metadata, result['lock_metadata'])
                self.assertEqual(decoded.binding, result['binding'])
                self.assertEqual(decoded.source_count, 38)
                self.assertEqual(decoded.packet_sha256, hashlib.sha256(raw).hexdigest())
                self.assertNotIn('a' * 32, repr(decoded))
                with self.assertRaises(AttributeError): decoded.source_count = 1
                done.append('actual_snapshot_data_roundtrip')

                # Exact framing boundaries only. These are NOT valid large Snapshot DATA.
                prefix = packet.MAGIC + struct.pack('!II', packet.MAX_HEADER, packet.MAX_PAYLOAD)
                framing = prefix + b'x' * packet.MAX_HEADER + b'y' * packet.MAX_PAYLOAD
                reader = packet.ObserverPacketReader()
                for offset in range(0, len(framing), 65536): reader.feed(framing[offset:offset + 65536])
                self.assertEqual(reader.size, len(framing))
                self.assertEqual(reader.expected, packet.PREFIX_BYTES + 65536 + 131072)
                self.assertEqual(b''.join(reader.parts), framing)
                with self.assertRaises(packet.ObserverPacketError) as caught: reader.finish()
                self.assertEqual(str(caught.exception), 'packet_header')
                for hsize, psize in ((0, 1), (1, 0), (65537, 1), (1, 131073)):
                    with self.subTest(capacity=(hsize, psize)):
                        value = packet.ObserverPacketReader()
                        with self.assertRaises(packet.ObserverPacketError) as caught:
                            value.feed(packet.MAGIC + struct.pack('!II', hsize, psize))
                        self.assertEqual(str(caught.exception), 'packet_lengths')
                        self.assertIs(value.failure, caught.exception)
                value = packet.ObserverPacketReader()
                value.feed(packet.MAGIC + struct.pack('!II', 1, 1))
                value.feed(b'xx')
                self.assertEqual(value.expected, packet.PREFIX_BYTES + 2)
                with self.assertRaises(packet.ObserverPacketError): value.finish()
                with self.assertRaises(packet.ObserverPacketError): packet.decode_packet(b'')
                with self.assertRaises(packet.ObserverPacketError): packet.decode_packet(b'x' * (packet.MAX_PACKET + 1))
                done.append('wire_capacity_no_truncation')

                hsize, psize = struct.unpack('!II', raw[len(packet.MAGIC):packet.PREFIX_BYTES])
                header_raw = raw[packet.PREFIX_BYTES:packet.PREFIX_BYTES + hsize]
                payload = raw[packet.PREFIX_BYTES + hsize:]
                for fault in ('epoch', 'nonce', 'cleanup', 'manifest', 'count', 'hash', 'key', 'permission'):
                    with self.subTest(header=fault):
                        header = domain.modules['p011_json'].loads(header_raw.decode('ascii'))
                        if fault == 'epoch': header['binding']['operation_epoch'] = 2
                        elif fault == 'nonce': header['binding']['nonce'] = 'z' * 32
                        elif fault == 'cleanup': header['binding']['cleanup_until'] = 35.1
                        elif fault == 'manifest': header['source_manifest_sha256'] = '0' * 64
                        elif fault == 'count': header['source_count'] = 37
                        elif fault == 'hash': header['payload_sha256'] = '0' * 64
                        elif fault == 'key': header['stable_key_sha256'] = '0' * 64
                        else: header['production_admitted'] = True
                        changed = packet._canonical(header)
                        wrong = packet.MAGIC + struct.pack('!II', len(changed), len(payload)) + changed + payload
                        with self.assertRaises(packet.ObserverPacketError): packet.decode_packet(wrong)
                done.append('binding_and_hash_refusals')

                reader = packet.ObserverPacketReader()
                for offset in range(0, len(raw), 127): reader.feed(raw[offset:offset + 127])
                self.assertEqual(reader.finish().private_snapshot_ascii(), result['snapshot_raw'])
                with self.assertRaises(packet.ObserverPacketError): reader.feed(b'x')
                with self.assertRaises(packet.ObserverPacketError): reader.finish()
                incomplete = packet.ObserverPacketReader(); incomplete.feed(raw[:-1])
                with self.assertRaises(packet.ObserverPacketError) as caught: incomplete.finish()
                self.assertIs(incomplete.failure, caught.exception)
                trailing = packet.ObserverPacketReader()
                with self.assertRaises(packet.ObserverPacketError) as caught: trailing.feed(raw + b'x')
                self.assertEqual(str(caught.exception), 'packet_trailing_data')
                self.assertIs(trailing.failure, caught.exception)
                done.append('stream_eof_data_not_reap')

                old_inventory = tuple(entry._ENTRY_INVENTORY)
                self.assertEqual(entry.main([]), 0)
                self.assertEqual(tuple(entry._ENTRY_INVENTORY), old_inventory)
                args = ['--collect', '--nonce', 'a' * 32, '--task-id', 'b' * 32,
                    '--native-epoch', '1', '--operation-epoch', '1', '--until', '30.0', '--cleanup-until', '35.0']
                self.assertEqual(entry._arguments(args), _binding())
                for wrong in (args + ['--output-fd', '4'], ['--collect'], args[:-1] + ['35.1']):
                    with self.assertRaises(entry.ReadonlyEntryError): entry._arguments(wrong)
                self.assertTrue(all(wire.call_count == 0 for wire in wires))
                done.append('default_main_and_fixed_arguments')

                for fault in ('not_fifo', 'read_access'):
                    with self.subTest(stdout=fault):
                        value, io, clock = writer()
                        if fault == 'not_fifo': io.output_meta.st_mode = stat.S_IFREG | 0o600
                        else: io.flags_value = 0
                        with self.assertRaises(entry.ReadonlyEntryError): value._adopt_stdout()
                        close_output(value, io)
                        self.assertEqual(io.close_counts, {} if fault == 'not_fifo' else {1: 1})
                        self.assertEqual(bool(value.output['unknown']), fault == 'not_fifo')
                done.append('fifo_and_access_refusals')

                value, io, clock = writer(); io.pipe_buf_value = 511
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._adopt_stdout()
                self.assertEqual(str(caught.exception), 'observer_stdout_atomic_cap')
                close_output(value, io)
                value, io, clock = writer(); value._adopt_stdout()
                io.output_meta.st_ino += 1
                with self.assertRaises(entry.ReadonlyEntryError): value._stdout_current()
                value._close(value.output, True)
                self.assertFalse(value.output['closed'])
                self.assertTrue(value.output['unknown'])
                self.assertEqual(io.close_counts, {})
                calls = tuple(io.calls); value._close(value.output, True)
                self.assertEqual(tuple(io.calls), calls)
                done.append('atomic_cap_and_metadata_refusals')

                value, io, clock = writer(); io.late_fstat = True
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._adopt_stdout()
                self.assertEqual(str(caught.exception), 'observer_expired')
                self.assertIsNotNone(value.output['metadata'])
                self.assertFalse(value.output['unknown'])
                self.assertFalse(any(call[0] == 'set_flags' for call in io.calls))
                close_output(value, io)
                self.assertIs(value.until, value.binding['until'])
                self.assertEqual(value.until, 30.0)
                done.append('late_return_original_close_only')

                value, io, clock = writer(); value._adopt_stdout()
                value.packet = value.packet_original = raw
                value._write_packet()
                self.assertEqual(b''.join(io.sent), raw)
                self.assertEqual(value.transmitted_bytes, len(raw))
                self.assertTrue(value.packet_written)
                self.assertTrue(value.write_attempted)
                self.assertTrue(all(asked <= 4096 and returned == asked for offset, asked, returned in value.output['write_returns']))
                calls, clock_calls = tuple(io.calls), clock.calls
                with self.assertRaises(entry.ReadonlyEntryError): value._write_packet()
                self.assertEqual(tuple(io.calls), calls)
                self.assertEqual(clock.calls, clock_calls)
                self.assertFalse(value.status()['parent_accepted'])
                self.assertFalse(value.status()['child_reaped'])
                close_output(value, io)
                done.append('complete_local_write_not_parent_acceptance')

                value, io, clock = writer(); value._adopt_stdout()
                value.packet = value.packet_original = raw
                original_error = OSError(errno.EAGAIN, 'HOST87 modeled zero-byte backpressure')
                io.eagain = original_error
                value._write_packet()
                self.assertIs(value.output['write_errors'][0][2], original_error)
                self.assertEqual(value.output['write_errors'][0][0], 0)
                self.assertEqual(value.output['write_returns'][0][0], 0)
                self.assertEqual(b''.join(io.sent), raw)
                close_output(value, io)
                value, io, clock = writer(); value._adopt_stdout(); io.backpressure = True
                value.packet = value.packet_original = raw
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._write_packet()
                self.assertEqual(str(caught.exception), 'observer_expired')
                self.assertEqual(io.sent, [])
                self.assertEqual(value.output['write_returns'], [])
                calls, clock_calls = tuple(io.calls), clock.calls
                with self.assertRaises(entry.ReadonlyEntryError): value._write_packet()
                self.assertEqual((tuple(io.calls), clock.calls), (calls, clock_calls))
                close_output(value, io)
                done.append('eagain_and_backpressure_original_cap')

                value, io, clock = writer(); value._adopt_stdout(); io.short_write = True
                value.packet = value.packet_original = raw
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._write_packet()
                self.assertEqual(str(caught.exception), 'observer_short_write')
                offset, asked, returned = value.output['write_returns'][0]
                self.assertEqual((offset, returned), (0, asked - 1))
                self.assertEqual(value.transmitted_bytes, returned)
                self.assertTrue(value.transmission_unknown)
                self.assertFalse(value.packet_written)
                calls, clock_calls = tuple(io.calls), clock.calls
                with self.assertRaises(entry.ReadonlyEntryError) as refusal: value._write_packet()
                self.assertEqual(str(refusal.exception), 'observer_write_already_attempted')
                self.assertEqual((tuple(io.calls), clock.calls), (calls, clock_calls))
                close_output(value, io)
                self.assertTrue(value.transmission_unknown)  # Physical close never launders transmission.
                done.append('short_write_retained_no_resume')

                value, io, clock = writer()
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._write_packet()
                self.assertEqual(str(caught.exception), 'observer_packet_limit')
                self.assertTrue(value.write_attempted)
                self.assertEqual(io.calls, [])
                self.assertEqual(clock.calls, 0)
                with self.assertRaises(entry.ReadonlyEntryError) as caught: value._write_packet()
                self.assertEqual(str(caught.exception), 'observer_write_already_attempted')
                self.assertEqual(io.calls, [])
                self.assertEqual(clock.calls, 0)
                done.append('invalid_packet_attempt_once_zero_io')

                value, io, clock = writer(); io.late_read = True
                with self.assertRaises(entry.ReadonlyEntryError) as caught:
                    value._read_source(entry.SOURCE_PINS[0])
                self.assertEqual(str(caught.exception), 'observer_expired')
                row = value.rows[0]
                self.assertIs(row['failure'], caught.exception)
                self.assertEqual(row['read_values'], [sources['mta_go_readonly_loader']])
                self.assertIsNone(row['raw'])
                self.assertTrue(row['closed'])
                self.assertFalse(row['unknown'])
                self.assertEqual(io.close_counts[row['fd']], 1)
                self.assertEqual(value.module_originals, [])
                self.assertEqual((value.until, value.cleanup_until), (30.0, 35.0))
                calls = tuple(io.calls); value._close(row)
                self.assertEqual(tuple(io.calls), calls)
                value, io, clock = writer()
                name = entry.SOURCE_PINS[0][0]
                foreign = types.ModuleType(name)
                self.assertNotIn(name, sys.modules)
                sys.modules[name] = foreign
                try:
                    with self.assertRaises(entry.ReadonlyEntryError) as caught:
                        value._load_module(entry.SOURCE_PINS[0])
                    self.assertEqual(str(caught.exception), 'observer_namespace_busy')
                    self.assertIs(sys.modules[name], foreign)
                    self.assertEqual(io.calls, [])
                    self.assertEqual(clock.calls, 0)
                finally:
                    if sys.modules.get(name) is foreign: del sys.modules[name]
                done.append('loader_source_late_and_no_namespace_adopt')
                self.assertTrue(all(wire.call_count == 0 for wire in wires))
            finally:
                domain.close()
        self.assertEqual(done, ['actual_snapshot_data_roundtrip', 'wire_capacity_no_truncation',
            'binding_and_hash_refusals', 'stream_eof_data_not_reap', 'default_main_and_fixed_arguments',
            'fifo_and_access_refusals', 'atomic_cap_and_metadata_refusals', 'late_return_original_close_only',
            'complete_local_write_not_parent_acceptance', 'eagain_and_backpressure_original_cap',
            'short_write_retained_no_resume', 'invalid_packet_attempt_once_zero_io',
            'loader_source_late_and_no_namespace_adopt'])
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
