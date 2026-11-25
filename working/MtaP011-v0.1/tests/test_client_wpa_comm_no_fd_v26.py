"""One new HOST model method; no old TestCase, real /proc, socket or RF.

Only the concrete v26 LinuxStatusSource public read/authentication protocol is
exercised. Fixture Actors, ProcObservations, OS metadata and errno are explicit
HOST assumptions, not P011 observations or receive/restoration admission.
The fixed original resource ledger constructs its own tickets and CloseProofs.
"""
import builtins
from contextlib import ExitStack
import errno
import hashlib
import importlib
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SOURCE = 'candidate/client-wpa-proc-vanish-v26/runtime/mta_client_wpa_status.py'
SOURCE_PIN = (44902, 'b1d9ce5ed37c7249952804f3bb2979fbb15492a57ac1514396bfa5d0e0103128')
FIXTURE = 'tests/test_client_wpa_status.py'
FIXTURE_PIN = (29939, 'fd5db1a405c2a74e16cb1d0394dcb943a1f1bec29ed25b7931fc32a315cdd872')
METHOD = 'test_known_absent_comm_policy_and_original_fd_proofs'
DOMAINS = 18
MARKER = ('HOST_WPA_COMM_NO_FD_V26 new_methods=1 domains=18 old_methods=0 '
          'os_fixture_model=true arm_read_flags=true device=false rf=false '
          'receive=false restoration=false\n')


def pinned(path, expected):
    raw = (BASE / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != expected:
        raise ValueError('HOST fixed input changed')
    return raw


def definitions():
    pinned(FIXTURE, FIXTURE_PIN)
    sys.path.insert(0, str(BASE / 'tests'))
    fixture = importlib.import_module('test_client_wpa_status')
    raw = pinned(SOURCE, SOURCE_PIN)
    modules = {'mta_client_baseline': fixture.wpa.baseline,
               'mta_client_proc': fixture.proc,
               'mta_p2p_client_init': fixture.core,
               'mta_p2p_client_ctrl': fixture.wpa.ctrl}
    original_import = builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules:
                raise ImportError('HOST fixed private dependency unavailable')
            return modules[name]
        return original_import(name, *args, **kwargs)
    value = types.ModuleType('host_private_wpa_comm_no_fd_v26')
    value.__file__ = str(BASE / SOURCE)
    value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
    # This private definition never replaces the canonical historical module.
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    if (value.baseline is not fixture.wpa.baseline or value.proc is not fixture.proc or
            value.core is not fixture.core or value.ctrl is not fixture.wpa.ctrl or
            value.baseline.proc is not value.proc or value.baseline.core is not value.core or
            sys.modules.get('mta_client_wpa_status') is not fixture.wpa):
        raise ValueError('HOST shared fixture realm changed')
    return fixture, value


class CommNoFdV26Tests(unittest.TestCase):
    def test_known_absent_comm_policy_and_original_fd_proofs(self):
        fixture, wpa = definitions()
        completed = 0
        deadline = 12.9
        missing_path = '/proc/2000/comm'
        clock = lambda: 10.1234567891
        rejected = (OSError, wpa.WpaStatusError, wpa.baseline.BaselineError)

        class DeadlineProc(fixture.FakeProc):
            # Adapt only the v25 deadline parameter. Observations remain the
            # original explicit HOST fixture objects in the shared realm.
            def read_self(inner, _absolute_deadline=None):
                self.assertEqual(_absolute_deadline, deadline)
                return fixture.FakeProc.read_self(inner)
            def read_actor(inner, pid, expected=None, _absolute_deadline=None):
                self.assertEqual(_absolute_deadline, deadline)
                return fixture.FakeProc.read_actor(inner, pid, expected)

        class ModelIO(fixture.FakeIO):
            def __init__(inner, error=None, daemon_missing=False):
                fixture.FakeIO.__init__(inner)
                inner.failure, inner.daemon_missing = error, daemon_missing
                inner.failure_path = '/proc/987/comm' if daemon_missing else missing_path
            def listdir(inner, value):
                result = fixture.FakeIO.listdir(inner, value)
                return result + ['2000'] if value == '/proc' and not inner.daemon_missing else result
            def open(inner, value, flags):
                if value == inner.failure_path and inner.failure is not None:
                    inner.calls.append(('open', value, flags))
                    raise inner.failure
                return fixture.FakeIO.open(inner, value, flags)

        def make(error=None, daemon_missing=False, self_missing=False):
            # A real bound ModelIO.open is retained by the original receipt;
            # replacing it with a plain function would invalidate the policy.
            io = ModelIO(error, daemon_missing)
            io.proc = DeadlineProc()
            path = io.failure_path
            if self_missing:
                def absent_self(_absolute_deadline=None):
                    self.assertEqual(_absolute_deadline, deadline)
                    raise OSError(errno.ESRCH, 'HOST required actor unavailable')
                io.proc.read_self = absent_self
            source = wpa.LinuxStatusSource(fixture.manifest(), _io=io,
                _proc_reader=io.proc, _clock=clock)
            return io, source, object(), path

        def successful_source(io, source, consumer, failure):
            original = source.read_source(consumer, deadline)
            self.assertIsNone(source.authenticate_source(consumer, original, deadline))
            files = source._files[-1]
            self.assertIs(files._tickets, files._tickets_original)
            self.assertIs(files._absent_discovery, files._absent_discovery_original)
            self.assertEqual(len(files._absent_discovery), 1)
            ticket, error = files._absent_discovery[0]
            self.assertIs(error, failure)
            self.assertTrue(any(row is ticket for row in files._tickets))
            self.assertIs(ticket['owner'], files)
            self.assertEqual(ticket['path'], missing_path)
            self.assertEqual(ticket['flags'], 0x88000)
            self.assertIs(ticket['open_error'], failure)
            self.assertIsNone(ticket['fd'])
            self.assertIs(ticket['attempted'], False)
            self.assertIs(ticket['closed'], True)
            self.assertIs(ticket['unknown'], False)
            self.assertIs(ticket['open_started'], True)
            self.assertIs(ticket['open_returned'], False)
            self.assertIsNone(ticket['open_result'])
            actual = tuple(row for row in files._tickets if type(row['fd']) is int)
            self.assertEqual(len(actual) + 1, len(files._tickets))
            self.assertEqual(sum(proof.expected for proof in original['files_closed']), len(actual))
            self.assertTrue(all(type(proof) is fixture.core.CloseProof and proof.complete()
                                for proof in original['files_closed']))
            for row in actual:
                self.assertIs(row['attempted'], True)
                self.assertIs(row['closed'], True)
                self.assertIs(row['unknown'], False)
                self.assertIn(row['fd'], io.created)
                self.assertEqual(io.closed.count(row['fd']), 1)
            self.assertEqual(io.live, {})
            self.assertNotIn('new_socket', io.calls)
            for unused, path, flags in (row for row in io.calls if type(row) is tuple and row[0] == 'open'):
                self.assertEqual(flags, 0x80000 if path == '/proc/987/exe' else 0x88000)
            return original, files, ticket

        def refusal(source, consumer):
            with self.assertRaises(rejected):
                source.read_source(consumer, deadline)
            self.assertEqual(source._issued, [])

        def bomb(*args, **kwargs):
            raise AssertionError('HOST actual OS/process/socket IO forbidden')

        with ExitStack() as stack:
            # Never patch the shared stdlib os object: unittest/linecache need
            # its real stat to retain and format the original failure trace.
            # Only production definition references receive a private proxy.
            private_os = types.SimpleNamespace(O_RDONLY=0, O_NOFOLLOW=0x8000,
                O_CLOEXEC=0x80000, open=bomb, read=bomb, fstat=bomb, stat=bomb,
                lstat=bomb, close=bomb, listdir=bomb, readlink=bomb, getpid=bomb,
                geteuid=bomb, uname=bomb, urandom=bomb)
            for module in (wpa, wpa.baseline, wpa.proc):
                stack.enter_context(mock.patch.object(module, 'os', private_os))
            stack.enter_context(mock.patch.object(wpa.socket, 'socket', side_effect=bomb))
            stack.enter_context(mock.patch.object(wpa.baseline.subprocess, 'Popen', side_effect=bomb))

            # Two actual source observations in one consumer epoch for each
            # eligible errno. No FD-close attempt is forged for absent opens.
            for number in (errno.ENOENT, errno.ESRCH):
                with self.subTest(domain='known_unopened', errno=number):
                    failure = OSError(number, 'HOST vanished comm before return')
                    io, source, consumer, unused = make(failure)
                    before, first, unused = successful_source(io, source, consumer, failure)
                    after, second, unused = successful_source(io, source, consumer, failure)
                    self.assertIsNot(before, after)
                    self.assertIsNot(first, second)
                    self.assertEqual(before['daemon_actor'].key(), after['daemon_actor'].key())
                    self.assertEqual(len(source._issued), 2)
                    self.assertEqual(len(io.closed), len(set(io.closed)))
                    completed += 1

            # Other errno and non-exact errno types are not discovery absence.
            for number in (errno.EACCES, None, True):
                with self.subTest(domain='unopened_reject', errno=number):
                    failure = OSError(number, 'HOST noneligible comm failure')
                    io, source, consumer, unused = make(failure)
                    refusal(source, consumer)
                    self.assertEqual(io.live, {})
                    self.assertEqual(source._files[0]._absent_discovery, [])
                    for row in source._files[0]._tickets:
                        if row['fd'] is None:
                            self.assertIs(row['attempted'], False)
                    completed += 1

            # Returning a real descriptor prevents the same errno becoming an
            # excluded no-FD ticket. Both read and pathname-stat failures close
            # that original FD exactly once, without issuing a source proof.
            for operation in ('read', 'stat'):
                for number in (errno.ENOENT, errno.EACCES):
                    with self.subTest(domain='returned_fd_reject', operation=operation, errno=number):
                        io, source, consumer, unused = make()
                        io.file(missing_path, b'unrelated\n')
                        failure = OSError(number, 'HOST error after actual descriptor return')
                        original = getattr(io, operation)
                        def broken(value, *args, _operation=operation, _original=original, **kwargs):
                            path = io.positions[value][0] if _operation == 'read' else value
                            if path == missing_path:
                                raise failure
                            return _original(value, *args, **kwargs)
                        setattr(io, operation, broken)
                        refusal(source, consumer)
                        files = source._files[0]
                        rows = [row for row in files._tickets if row.get('path') == missing_path]
                        self.assertEqual(len(rows), 1)
                        row = rows[0]
                        self.assertIs(type(row['fd']), int)
                        self.assertIs(row['open_returned'], True)
                        self.assertIs(row['attempted'], True)
                        self.assertIs(row['closed'], True)
                        self.assertEqual(io.closed.count(row['fd']), 1)
                        self.assertEqual(files._absent_discovery, [])
                        self.assertEqual(io.live, {})
                        completed += 1

            # Authentication consumes the original ledger, not an aggregate
            # proof bool. Mutating an excluded original invalidates its source.
            for field, value in (('attempted', True), ('unknown', True),
                                 ('closed', False), ('open_returned', True)):
                with self.subTest(domain='forged_ticket_flag', field=field):
                    failure = OSError(errno.ENOENT, 'HOST vanished comm')
                    io, source, consumer, unused = make(failure)
                    original, files, ticket = successful_source(io, source, consumer, failure)
                    ticket[field] = value
                    with self.assertRaises(wpa.WpaStatusError):
                        source.authenticate_source(consumer, original, deadline)
                    self.assertEqual(io.live, {})
                    completed += 1

            for kind in ('duplicate_ticket', 'duplicate_receipt', 'foreign_ticket'):
                with self.subTest(domain='excluded_inventory_reject', kind=kind):
                    failure = OSError(errno.ENOENT, 'HOST vanished comm')
                    io, source, consumer, unused = make(failure)
                    original, files, ticket = successful_source(io, source, consumer, failure)
                    if kind == 'duplicate_ticket':
                        files._tickets.append(ticket)
                    elif kind == 'duplicate_receipt':
                        files._absent_discovery.append((ticket, failure))
                    else:
                        files._absent_discovery[0] = (dict(ticket), failure)
                    with self.assertRaises(wpa.WpaStatusError):
                        source.authenticate_source(consumer, original, deadline)
                    self.assertEqual(io.live, {})
                    completed += 1

            with self.subTest(domain='required_daemon_missing'):
                failure = OSError(errno.ENOENT, 'HOST original daemon comm missing')
                io, source, consumer, unused = make(failure, daemon_missing=True)
                refusal(source, consumer)
                self.assertNotIn('new_socket', io.calls)
                self.assertEqual(io.live, {})
                completed += 1

            with self.subTest(domain='required_self_actor_missing'):
                io, source, consumer, unused = make(self_missing=True)
                refusal(source, consumer)
                self.assertNotIn('new_socket', io.calls)
                self.assertTrue(source._pending)
                completed += 1

        self.assertEqual(completed, DOMAINS)
        print(MARKER, end='')


if __name__ == '__main__':
    # Select exactly this new method, never discovery over imported old tests.
    suite = unittest.TestSuite([CommNoFdV26Tests(METHOD)])
    outcome = unittest.TextTestRunner(verbosity=0).run(suite)
    sys.exit(0 if outcome.wasSuccessful() else 1)
