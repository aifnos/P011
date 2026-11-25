"""New narrow v30-r2 passive FIFO HOST test; no launch/child/restore claim.

Actual PC pipe create, nonblocking flag readback, dev/ino/mode fstat, read,
close and EBADF are used. Windows portability fields st_uid/st_gid/st_nlink/
st_rdev are explicitly modeled as 0/0/1/0, never described as actual OS facts
(including any subset Python may expose). The Actor/released watchdog
prerequisites are explicitly modeled;
they are NOT fabricated evidence of a launched child, Proc identity, network
permission, fresh_exit, full close_inventory or native CLIENT recovery. Only
the actual native passive and descriptor-close helpers execute. Synthetic
clock delay tests a returned read after the local cap, not wall-time limits.
Old/frozen TestCase methods never execute. The 35-definition fixture is loaded
by AST-selection of pinned constants/functions, not by importing its TestCase.
"""
import ast
import builtins
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
DEFINITION_PATH = 'tests/test_client_transfer_dispose_v30_r2.py'
DEFINITION_SHA = '3d6aa251a56d352b9590d22703f2596f4fd46c0beda2667da657df5b2b001af6'


def load_definitions():
    raw = (BASE / DEFINITION_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != DEFINITION_SHA:
        raise ValueError('HOST helper definitions changed')
    tree = ast.parse(raw.decode('utf-8'))
    names = {'MANIFEST_PATH', 'MANIFEST_SHA', 'REPLACEMENTS', 'APPENDED'}
    selected = [node for node in tree.body if
        isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets) or
        isinstance(node, ast.FunctionDef) and node.name in ('fixed', 'definitions')]
    if len(selected) != 6 or any(isinstance(n, (ast.ClassDef, ast.Import, ast.ImportFrom)) for n in selected):
        raise ValueError('HOST definition selection changed')
    ns = {'BASE': BASE, 'ast': ast, 'builtins': builtins, 'hashlib': hashlib, 'json': json, 'types': types}
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(module, 'HOST-v30-r2-fixed-definition-selection', 'exec'), ns)
    return ns['definitions']()


class SyntheticClock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class ActualFifoOS:
    """Actual PC FIFO IO; Linux flag bit/missing Windows fields are modeled."""
    O_NONBLOCK = 0x800
    def __init__(self, clock, late):
        self.clock, self.late = clock, late
        self.reads, self.closes, self.stats, self.nonblocking = [], [], [], []
    def getpid(self): return os.getpid()
    def fstat(self, fd):
        self.stats.append(fd)
        value = os.fstat(fd)
        if os.name != 'nt': return value
        # Deliberate modeled portability fields, not getattr default values or
        # a claim that all Windows Python versions expose the same subset.
        return types.SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
            st_mode=value.st_mode, st_uid=0, st_gid=0, st_nlink=1, st_rdev=0)
    def set_inheritable(self, fd, value): return os.set_inheritable(fd, value)
    def get_inheritable(self, fd): return os.get_inheritable(fd)
    def flags(self, fd):
        blocking = os.get_blocking(fd)
        self.nonblocking.append((fd, blocking))
        return 0 if blocking else self.O_NONBLOCK
    def read(self, fd, amount):
        self.reads.append((fd, amount))
        data = os.read(fd, amount)
        if self.late: self.clock.now += .3
        return data
    def close(self, fd):
        self.closes.append(fd)
        return os.close(fd)


class NoProcReader:
    def __init__(self): self.calls = []
    def read_self(self, *args, **kwargs):
        self.calls.append('read_self')
        raise AssertionError('passive helper must not read Proc')
    def read_actor(self, *args, **kwargs):
        self.calls.append('read_actor')
        raise AssertionError('passive helper must not read Proc')


class ClientOwnerPassiveV30R2Tests(unittest.TestCase):
    def test_native_passive_bad_or_late_fifo_stops_without_poisoning_known_fd_onceclose(self):
        modules, _ = load_definitions()
        owner_module, core = modules['mta_client_process_owner'], modules['mta_p2p_client_init']
        for case in ('bad_payload', 'late_read'):
            with self.subTest(case=case):
                read_fd, write_fd = os.pipe()
                clock, reader = SyntheticClock(), NoProcReader()
                platform = ActualFifoOS(clock, case == 'late_read')
                descriptor_closed = False
                try:
                    os.set_blocking(read_fd, False)
                    self.assertFalse(os.get_blocking(read_fd))
                    self.assertTrue(stat.S_ISFIFO(os.fstat(read_fd).st_mode))
                    original_pid = os.getpid()
                    owner = owner_module.DirectChildOwner(_os=platform, _reader=reader,
                        _clock=clock, _threads=lambda: 1, _flags=platform.flags)
                    spec = owner_module.LaunchSpec('watchdog', '/HOST/watchdog',
                        ('/HOST/watchdog',), (), '1' * 64)
                    ticket = owner.register(spec, read_fd, 400.0)
                    # Modeled prerequisites only. No real child is launched,
                    # no Actor/Proc proof or native network grant is asserted.
                    ticket.parent = core.Actor(original_pid, 10, '/HOST/parent',
                        '2' * 64, ((original_pid, 10, 'S'),))
                    ticket.boot, ticket.released = '3' * 32, True
                    record = owner._new_fd(ticket, 'notify_read', os.read)
                    self.assertIs(owner._fd_return(ticket, record, read_fd), record)
                    original_metadata = record.metadata
                    self.assertIs(owner._tickets[0], ticket)
                    self.assertEqual(1, len(ticket.fds))
                    self.assertIs(ticket.fds[0], record)
                    payload = b'X' if case == 'bad_payload' else b'R'
                    self.assertEqual(1, os.write(write_fd, payload))
                    before_stats = len(platform.stats)
                    with self.assertRaises(owner_module.ProcessOwnerError) as failure:
                        owner_module.DirectChildOwner.read_requests_passive_v30(owner, ticket, 400.0)
                    self.assertEqual('fd_unknown' if case == 'bad_payload' else 'deadline', str(failure.exception))
                    self.assertEqual('invalid_data' if case == 'bad_payload' else 'deadline', ticket.notify_failure_v30)
                    self.assertFalse(ticket.unknown); self.assertFalse(record.unknown)
                    self.assertFalse(record.attempted); self.assertFalse(record.closed)
                    self.assertEqual(original_metadata, owner_module._meta(platform.fstat(read_fd)))
                    self.assertEqual([(read_fd, 17)], platform.reads)
                    self.assertGreater(len(platform.stats), before_stats)
                    self.assertIs(ticket.notify_last_v30['fd_record'], record)
                    self.assertTrue(ticket.notify_last_v30['read_started'])
                    self.assertTrue(ticket.notify_last_v30['returned'])
                    self.assertEqual(payload, ticket.notify_last_v30['data'])
                    self.assertTrue(ticket.notify_last_v30['unknown'])  # Observation failed, not identity proof.
                    self.assertEqual(0 if case == 'bad_payload' else 1, ticket.notify_requests)
                    self.assertFalse(ticket.notify_eof_v30)
                    self.assertEqual(400.0, ticket.deadline)
                    self.assertFalse(reader.calls); self.assertFalse(platform.closes)
                    # Sticky failure is stop-only, after a NEW same-worker/PID/
                    # original FD/metadata/nonblocking check under a valid cap.
                    before_stats, before_reads = len(platform.stats), len(platform.reads)
                    self.assertIs(True, owner_module.DirectChildOwner.read_requests_passive_v30(owner, ticket, 400.0))
                    self.assertGreater(len(platform.stats), before_stats)
                    self.assertEqual(before_reads, len(platform.reads))
                    self.assertFalse(ticket.unknown); self.assertFalse(record.unknown)
                    self.assertFalse(ticket.waited); self.assertFalse(ticket.exit_verified)
                    self.assertFalse(owner.status()['complete']); self.assertFalse(owner.status()['provider_ready'])
                    # Actual native close helper still freshly compares the
                    # original metadata, performs ONE actual close, sees EBADF.
                    self.assertIs(True, owner_module.DirectChildOwner._close_fd(owner, ticket, record))
                    descriptor_closed = record.closed
                    self.assertTrue(record.attempted); self.assertTrue(record.closed)
                    self.assertFalse(ticket.unknown); self.assertFalse(record.unknown)
                    self.assertEqual([read_fd], platform.closes)
                    with self.assertRaises(OSError) as actual:
                        os.fstat(read_fd)
                    self.assertEqual(errno.EBADF, actual.exception.errno)
                    stats_after_close = len(platform.stats)
                    self.assertIs(True, owner_module.DirectChildOwner._close_fd(owner, ticket, record))
                    self.assertEqual([read_fd], platform.closes)
                    self.assertEqual(stats_after_close, len(platform.stats))
                    self.assertFalse(reader.calls)
                finally:
                    if not descriptor_closed: os.close(read_fd)
                    os.close(write_fd)


if __name__ == '__main__':
    unittest.main()

