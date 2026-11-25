"""Only the two actual methods over FakeIO; no P011/performance proof."""
import ast
import errno
import importlib.util
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_baseline as old

PATH = BASE / 'candidate/client-readparts-v6/runtime/mta_client_baseline.py'
spec = importlib.util.spec_from_file_location('client_readparts_v6_baseline', str(PATH))
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


class Io(old.FakeIo):
    def __init__(self, chunk=3):
        old.FakeIo.__init__(self)
        self.chunk, self.reads, self.override = chunk, [], None
    def read(self, fd, count):
        path = self.fds[fd][1]
        value = old.FakeIo.read(self, fd, min(count, self.chunk))
        self.reads.append((path, count, value))
        return self.override(self, path, count, value) if self.override else value


class ReadPartsV6Tests(unittest.TestCase):
    def setUp(self):
        for name in ('validate', 'open', 'read', 'fstat', 'stat', 'close', 'listdir', 'socket', 'readable', 'spawn'):
            patcher = mock.patch.object(b._LinuxIo, name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('socket.socket', 'subprocess.Popen', 'select.select', 'ctypes.CDLL'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('read_self', 'read_actor'):
            patcher = mock.patch.object(b.proc.ProcReader, name, side_effect=AssertionError('actual proc forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(b.hashlib, 'sha256', side_effect=old.fake_hash)
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, data=b'abcdefg', chunk=3):
        io, reader = Io(chunk), old.FakeReader()
        io.nodes['/fixture'] = (data, old.metadata(900, stat.S_IFREG | 0o444, len(data)))
        collector = b.BaselineCollector(old.MANIFEST, _io=io, _reader=reader, _clock=io.clock)
        collector._deadline = io.clock() + 5
        return collector, io, reader

    def image(self, collector, io, reader):
        actor = reader.read_actor(101).actor
        data, row, meta = collector._read_file(actor.exe, b.MAX_FILE, binary=True)
        collector._binaries[actor.exe] = (row, meta, collector._binary_parents(actor.exe))
        io.reads[:] = []
        return actor

    def once_closed(self, collector, io):
        self.assertFalse(io.fds)
        self.assertEqual(len(io.closed), len(set(io.closed)))
        self.assertTrue(all(row['attempted'] and row['closed'] for row in collector._tickets))
        before = list(io.closed)
        self.assertTrue(collector.close())
        self.assertEqual(before, io.closed)

    def test_multichunk_exact_result_raw_and_remaining_limit_requests(self):
        collector, io, reader = self.make()
        data, row, meta = collector._read_file('/fixture', 7)
        self.assertEqual(b'abcdefg', data)
        self.assertEqual([8, 5, 2, 1], [count for path, count, chunk in io.reads])
        self.assertEqual([b'abc', b'def', b'g', b''], [chunk for path, count, chunk in io.reads])
        self.assertEqual(('file', '/fixture', data, meta), collector._raw[-1])
        self.assertTrue(row['closed']); self.once_closed(collector, io)

    def test_empty_zero_limit_and_exact_boundary_remain_valid(self):
        for data, limit in ((b'', 0), (b'abc', 3)):
            with self.subTest(limit=limit):
                collector, io, reader = self.make(data)
                self.assertEqual(data, collector._read_file('/fixture', limit)[0])
                self.assertEqual(b'', io.reads[-1][2])
                self.assertEqual(1, io.reads[-1][1]); self.once_closed(collector, io)

    def test_limit_plus_one_rejects_before_raw_acceptance_and_closes_once(self):
        collector, io, reader = self.make(b'abcdefgh')
        with self.assertRaises(b.BaselineError) as caught: collector._read_file('/fixture', 7)
        self.assertEqual('file_budget', caught.exception.code)
        self.assertEqual([8, 5, 2], [count for path, count, chunk in io.reads])
        self.assertEqual([], collector._raw); self.once_closed(collector, io)

    def test_invalid_type_or_over_count_chunk_rejected_in_both_methods(self):
        for mode in ('file', 'image'):
            for bad in (bytearray(b'x'), None, b'x' * 65537):
                with self.subTest(mode=mode, kind=type(bad).__name__):
                    collector, io, reader = self.make()
                    actor = self.image(collector, io, reader) if mode == 'image' else None
                    io.override = lambda *args: bad
                    with self.assertRaises(b.BaselineError) as caught:
                        if mode == 'image': collector._actor_image(actor)
                        else: collector._read_file('/fixture', 7)
                    self.assertEqual('file_budget', caught.exception.code); self.once_closed(collector, io)

    def test_post_eof_metadata_change_rejected_in_both_methods(self):
        for mode in ('file', 'image'):
            with self.subTest(mode=mode):
                collector, io, reader = self.make()
                actor = self.image(collector, io, reader) if mode == 'image' else None
                def alter(io, path, count, value):
                    if not value: io.nodes[path][1].st_ino += 1
                    return value
                io.override = alter
                with self.assertRaises(b.BaselineError) as caught:
                    if mode == 'image': collector._actor_image(actor)
                    else: collector._read_file('/fixture', 7)
                self.assertEqual('file_identity', caught.exception.code); self.once_closed(collector, io)

    def test_actor_full_multichunk_reread_digest_and_hash_change_still_rejected(self):
        collector, io, reader = self.make()
        actor = self.image(collector, io, reader)
        collector._actor_image(actor)
        image_raw = collector._raw[-1]
        self.assertEqual(('actor_image', '/proc/101/exe', dict(old.MANIFEST)[actor.exe]), image_raw[:3])
        self.assertEqual(old.STOCK_BYTES[actor.exe], b''.join(row[2] for row in io.reads))
        self.assertGreater(len(io.reads), 2)
        self.once_closed(collector, io)
        collector, io, reader = self.make(); actor = self.image(collector, io, reader)
        path = '/proc/101/exe'; data, meta = io.nodes[path]
        io.nodes[path] = (b'x' * len(data), meta)
        with self.assertRaises(b.BaselineError) as caught: collector._actor_image(actor)
        self.assertEqual('file_pin', caught.exception.code); self.once_closed(collector, io)

    def test_actor_empty_or_max_plus_one_still_rejected_with_original_close(self):
        for empty in (True, False):
            with self.subTest(empty=empty):
                collector, io, reader = self.make(); actor = self.image(collector, io, reader)
                if empty:
                    path = '/proc/101/exe'; unused, meta = io.nodes[path]; io.nodes[path] = (b'', meta)
                    with self.assertRaises(b.BaselineError) as caught: collector._actor_image(actor)
                    self.assertEqual('file_pin', caught.exception.code)
                else:
                    with mock.patch.object(b, 'MAX_FILE', 3), self.assertRaises(b.BaselineError) as caught:
                        collector._actor_image(actor)
                    self.assertEqual('file_budget', caught.exception.code)
                    self.assertEqual([4, 1], [row[1] for row in io.reads])
                self.once_closed(collector, io)

    def test_io_exception_baseexception_and_retain_preserve_once_owner(self):
        for mode in ('file', 'image'):
            for error in (OSError(errno.EIO, 'HOST'), KeyboardInterrupt('HOST')):
                with self.subTest(mode=mode, kind=type(error).__name__):
                    collector, io, reader = self.make()
                    actor = self.image(collector, io, reader) if mode == 'image' else None
                    def fail(io, path, count, value): raise error
                    io.override = fail
                    with self.assertRaises(type(error)):
                        if mode == 'image': collector._actor_image(actor)
                        else: collector._read_file('/fixture', 7)
                    self.once_closed(collector, io)
        collector, io, reader = self.make()
        data, row, meta = collector._read_file('/fixture', 7, retain=True)
        self.assertFalse(row['attempted']); self.assertIn(row['fd'], io.fds)
        self.assertTrue(collector.close()); self.once_closed(collector, io)

    def test_complete_collect_keeps_four_manifest_reads_four_rehashes_and_each_image(self):
        collector, io, reader = self.make(chunk=7)
        result = collector.collect(6)
        self.assertIs(type(result), b.core.Snapshot)
        for path, pin in old.MANIFEST:
            self.assertEqual(2, sum(row[0] == 'file' and row[1] == path for row in collector._raw))
        for path in ('/proc/101/exe', '/proc/102/exe'):
            self.assertEqual(2, sum(row[0] == 'actor_image' and row[1] == path for row in collector._raw))
        self.assertEqual(2, len(collector._rounds)); self.once_closed(collector, io)

    def test_exact_loop_replacements_only_python35_and_five_second_budget(self):
        before = (BASE / 'candidate/client-actor-v5/runtime/mta_client_baseline.py').read_bytes()
        after = PATH.read_bytes()
        replacements = (
            (b"        row, data = self._open(path), b''\n", b"        parts, total = [], 0\n        row = self._open(path)\n"),
            (b"                count = min(65536, limit + 1 - len(data))\n", b"                count = min(65536, limit + 1 - total)\n"),
            (b"                data += chunk\n                if len(data) > limit: _fail('file_budget')\n",
             b"                parts.append(chunk); total += len(chunk)\n                if total > limit: _fail('file_budget')\n"),
            (b"                if not chunk: break\n            if _metadata(self._io.fstat(row['fd']))",
             b"                if not chunk: break\n            data = b''.join(parts)\n            if _metadata(self._io.fstat(row['fd']))"),
            (b"        row, data = self._open(path, _EXEC_READ_FLAGS), b''\n", b"        parts, total = [], 0\n        row = self._open(path, _EXEC_READ_FLAGS)\n"),
            (b"                self._now(); count = min(65536, MAX_FILE + 1 - len(data))\n",
             b"                self._now(); count = min(65536, MAX_FILE + 1 - total)\n"),
            (b"                data += chunk\n                if len(data) > MAX_FILE: _fail('file_budget')\n",
             b"                parts.append(chunk); total += len(chunk)\n                if total > MAX_FILE: _fail('file_budget')\n"),
            (b"                if not chunk: break\n            digest = hashlib.sha256(data).hexdigest()\n",
             b"                if not chunk: break\n            data = b''.join(parts)\n            digest = hashlib.sha256(data).hexdigest()\n"))
        reverse = after
        for left, right in replacements:
            self.assertEqual(1, reverse.count(right)); reverse = reverse.replace(right, left, 1)
        self.assertEqual(before, reverse)
        self.assertEqual('3e1575d94020bf9e1e54a9fca2ca35876efbcb1385a15dd0bc0bfdf8ac8736ea', old.REAL_SHA(before).hexdigest())
        for source in (after, Path(__file__).read_bytes()): ast.parse(source.decode('utf-8'), feature_version=(3, 5))
        self.assertEqual(5.0, b.BaselineCollector(old.MANIFEST)._timeout)


if __name__ == '__main__': unittest.main()
