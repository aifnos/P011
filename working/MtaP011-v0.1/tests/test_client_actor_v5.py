"""Fresh Actor state tests: real collect + ProcReader over synthetic FakeFS.

No actual proc, netlink, child, pin image or P011 evidence is issued here.
Raw stat bytes carry each scenario's states; none are normalized or rewritten
after the actual readers return their observations.
"""
import ast
import errno
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_baseline as old
import test_client_proc as pf
import mta_client_journal_codec as codec

PATH = BASE / 'candidate/client-actor-v5/runtime/mta_client_baseline.py'
spec = importlib.util.spec_from_file_location('client_actor_v5_baseline', str(PATH))
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


class Fs(pf.FakeFs):
    def __init__(self):
        pf.FakeFs.__init__(self)
        self.files[pf.BOOT_PATH] = old.BOOT.encode('ascii') + b'\n'
        self.actor(42, 'python3')

    def actor(self, number, name, state='S', change=None):
        root = '/proc/' + str(number)
        prefix = root + '/'
        self.dirs = {p for p in self.dirs if p != root and not p.startswith(prefix)}
        for mapping in (self.files, self.links):
            for path in tuple(mapping):
                if path.startswith(prefix): del mapping[path]
        self.dirs.update((root, root + '/task'))
        start = number + 100 + int(change == 'leader_start')
        worker = number + 1000 + int(change == 'tid')
        tasks = ((number, start),) if number == 42 else (
            (number, start), (worker, worker + 100 + int(change == 'task_start')))
        exe = ('/usr/alt/' if change == 'exe' else '/usr/bin/') + name
        self.links[root + '/exe'] = exe
        command = (exe + ('\0changed\0' if change == 'argv' else '\0argument\0')).encode('ascii')
        self.files[root + '/cmdline'] = command
        self.files[root + '/stat'] = pf.stat_data(number, start, state, threads=len(tasks))
        for tid, task_start in tasks:
            path = root + '/task/' + str(tid)
            self.dirs.add(path)
            self.files[path + '/stat'] = pf.stat_data(tid, task_start, state, threads=len(tasks))


class Reader(object):
    """Only chooses raw fixture before invoking the unchanged actual reader."""
    def __init__(self, mode='image_rs', fault=None):
        self.fs, self.mode, self.fault = Fs(), mode, fault
        self.reader = b.proc.ProcReader(_fs=self.fs, _clock=lambda: 1.0)
        self.self_calls = 0

    def read_self(self):
        self.self_calls += 1
        return self.reader.read_self()

    def read_actor(self, number, expected=None):
        names = {101: 'Z03', 102: 'control_engine', 103: 'weston'}
        state, change = 'S', None
        if self.mode == 'image_rs': state = 'R' if expected is None else 'S'
        elif self.mode == 'round_sr': state = 'S' if self.self_calls < 3 else 'R'
        elif self.mode == 'image_fault' and number == 101 and expected is not None:
            if self.fault in ('Z', 'X', 'P'): state = self.fault
            else: change = self.fault
        elif self.mode == 'round_fault' and number == 103 and self.self_calls >= 3:
            change = self.fault
        self.fs.actor(number, names[number], state, change)
        return self.reader.read_actor(number, expected)


class ActorV5Tests(unittest.TestCase):
    def setUp(self):
        for name in ('validate', 'open', 'read', 'fstat', 'stat', 'close', 'listdir', 'socket', 'readable', 'spawn'):
            patcher = mock.patch.object(b._LinuxIo, name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for target in ('os.open', 'os.read', 'os.close', 'os.fstat', 'os.lstat', 'os.listdir', 'os.readlink',
                'socket.socket', 'subprocess.Popen', 'select.select', 'ctypes.CDLL'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS/proc forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(b.hashlib, 'sha256', side_effect=old.fake_hash)
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, mode='image_rs', fault=None):
        io, reader = old.FakeIo(), Reader(mode, fault)
        collector = b.BaselineCollector(old.MANIFEST, _io=io, _reader=reader, _clock=io.clock)
        return collector, io, reader

    def closed(self, collector, io, reader):
        self.assertFalse(io.fds)
        self.assertFalse(reader.fs.live)
        self.assertFalse(reader.reader._pending)
        self.assertTrue(all(row['closed'] and not row['unknown'] for row in collector._tickets))
        for fs, descriptor in reader.reader._fd_refs:
            self.assertIs(fs, reader.fs)
            with self.assertRaises(OSError) as caught: fs.fstat(descriptor)
            self.assertEqual(errno.EBADF, caught.exception.errno)

    def test_actor_image_r_to_s_identity_live_and_raw_states_preserved(self):
        collector, io, reader = self.make()
        result = collector.collect(6.0)
        self.assertTrue(collector.status()['read_success'])
        for number in (101, 102):
            observed = [v.actor for v in collector._observations if v.actor is not None and v.actor.pid == number]
            self.assertEqual(['R', 'S', 'R', 'S'], [a.tasks[0][2] for a in observed])
            self.assertTrue(all(a.key() == observed[0].key() and a.live() for a in observed))
        raw = tuple(row.data for value in collector._observations for row in value.raw if type(row.data) is bytes)
        self.assertTrue(any(b') R ' in row for row in raw))
        self.assertTrue(any(b') S ' in row for row in raw))
        self.assertEqual('R', result.stock_actors[0].tasks[0][2])
        self.closed(collector, io, reader)

    def test_two_round_s_to_r_preserves_full_state_but_stable_key_passes(self):
        collector, io, reader = self.make('round_sr')
        result = collector.collect(6.0)
        first = collector._rounds[0]
        self.assertEqual(first.key(), result.key())
        self.assertEqual(('S', 'R'), (first.stock_actors[0].tasks[0][2], result.stock_actors[0].tasks[0][2]))
        self.assertNotEqual(first.stock_actors[0].tasks, result.stock_actors[0].tasks)
        self.closed(collector, io, reader)

    def test_image_tid_start_argv_exe_changes_still_rejected_by_real_proc(self):
        for fault in ('tid', 'task_start', 'leader_start', 'argv', 'exe'):
            with self.subTest(fault=fault):
                collector, io, reader = self.make('image_fault', fault)
                with self.assertRaises(b.BaselineError): collector.collect(6.0)
                self.assertFalse(collector.status()['read_success'])
                self.assertFalse(io.processes)
                self.closed(collector, io, reader)

    def test_final_round_task_identity_argv_exe_changes_still_rejected(self):
        for fault in ('tid', 'task_start', 'leader_start', 'argv', 'exe'):
            with self.subTest(fault=fault):
                collector, io, reader = self.make('round_fault', fault)
                with self.assertRaises(b.BaselineError) as caught: collector.collect(6.0)
                self.assertEqual('snapshot_changed', caught.exception.code)
                self.assertEqual(2, len(collector._rounds))
                self.assertFalse(collector.status()['read_success'])
                self.closed(collector, io, reader)

    def test_z_x_p_refused_by_original_proc_contract_without_fake_actor(self):
        for state, reason in (('Z', 'nonlive_task'), ('X', 'nonlive_task'), ('P', 'unsupported_actor_state')):
            with self.subTest(state=state):
                collector, io, reader = self.make('image_fault', state)
                with self.assertRaises(b.BaselineError) as caught: collector.collect(6.0)
                self.assertEqual('actor_unknown', caught.exception.code)
                self.assertEqual(reason, collector._observations[-1].reason)
                self.assertNotEqual('live_actor', collector._observations[-1].kind)
                self.closed(collector, io, reader)

    def test_persisted_journal_codec_and_cas_keep_raw_task_state_strict(self):
        collector, io, reader = self.make('round_sr')
        result = collector.collect(6.0)
        identity = b.core.Identity('a' * 64)
        first = b.core.Journal(identity, 'prepared', collector._rounds[0], 10)
        second = b.core.Journal(identity, 'prepared', result, 10)
        self.assertEqual(first.baseline.key(), second.baseline.key())
        self.assertFalse(b.core._same_journal(first, second))
        first_wire, second_wire = codec.encode_journal(first), codec.encode_journal(second)
        self.assertNotEqual(first_wire, second_wire)
        self.assertTrue(b.core._same_journal(first, codec.decode_journal(first_wire)))
        self.assertTrue(b.core._same_journal(second, codec.decode_journal(second_wire)))
        self.closed(collector, io, reader)

    def test_exact_two_predicate_diff_python35_and_old_core_proc_unchanged(self):
        before = (BASE / 'candidate/client-baseline-v3/runtime/mta_client_baseline.py').read_bytes()
        after = PATH.read_bytes()
        changes = (
            (b"            if fresh.actor.key() != actor.key() or fresh.actor.tasks != actor.tasks: _fail('actor_changed')\n",
             b"            if fresh.actor.key() != actor.key() or not fresh.actor.live() or not actor.live(): _fail('actor_changed')\n"),
            (b"            if tuple(sorted((a.pid, a.tasks) for a in self._rounds[0].stock_actors)) != \\\n                    tuple(sorted((a.pid, a.tasks) for a in result.stock_actors)): _fail('snapshot_changed')\n",
             b"            if tuple(sorted(a.key() for a in self._rounds[0].stock_actors)) != \\\n                    tuple(sorted(a.key() for a in result.stock_actors)) or any(\n                        not a.live() for a in self._rounds[0].stock_actors + result.stock_actors): _fail('snapshot_changed')\n"))
        reversed_source = after
        for old_bytes, new_bytes in changes:
            self.assertEqual(1, reversed_source.count(new_bytes))
            reversed_source = reversed_source.replace(new_bytes, old_bytes)
        self.assertEqual(before, reversed_source)
        self.assertEqual('ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a', old.REAL_SHA(before).hexdigest())
        for name, pin in (('mta_p2p_client_init.py', 'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
                          ('mta_client_proc.py', '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591')):
            self.assertEqual(pin, old.REAL_SHA((BASE / 'runtime' / name).read_bytes()).hexdigest())
        for source in (after, Path(__file__).read_bytes()): ast.parse(source.decode('utf-8'), feature_version=(3, 5))
        self.assertEqual(5.0, b.BaselineCollector(old.MANIFEST)._timeout)


if __name__ == '__main__': unittest.main()
