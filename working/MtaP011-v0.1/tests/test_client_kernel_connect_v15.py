"""New HOST-only v15 methods; actual candidate reader over retained Fake OS."""
import ast
import errno
import hashlib
import importlib.util
import threading
import unittest

import test_client_kernel_proof_v13 as old

BASE = old.BASE
PATH = BASE / 'candidate/client-kernel-connect-v15/runtime/mta_client_kernel_proof.py'
BASELINE = old.PATH
BASELINE_SHA = '14dbe98d59e8319812e62d75907196b78fbde348f40003942476ecb9ee9c0f93'
spec = importlib.util.spec_from_file_location('private_kernel_connect_v15', str(PATH))
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)


class KernelConnectV15Tests(unittest.TestCase):
    # Reuse only the tripwire/fixture definitions, not any old test methods.
    setUp = old.KernelProofTests.setUp

    def make(self, io=None, clock=None, checkpoint=None, deadline=None,
             timeout=5.0, after_proc=None):
        io = io or old.FakeIo()
        readers = []
        def factory(timeout, _clock):
            reader = old.proc.ProcReader(timeout=timeout, _clock=_clock,
                _fs=old.proc_fixture.FakeFs())
            readers.append(reader)  # Exact producer retained before actual read.
            read_self = reader.read_self
            def observed():
                value = read_self()
                if after_proc is not None:
                    after_proc(reader, value, len(readers))
                return value
            reader.read_self = observed
            return reader
        owner, epoch = object(), 100000001
        reader = k.ClientKernelReader(old.origin(), old.BOOT, owner, epoch,
            timeout=timeout, _io=io, _proc_factory=factory,
            _clock=clock or (lambda: 100.0), _checkpoint=checkpoint,
            _deadline=deadline)
        return reader, io, readers, owner, epoch

    def rejected(self, reader, code):
        with self.assertRaises(k.KernelReadError) as caught:
            reader.read()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        self.assertFalse(reader.status()['read_success'])
        self.assertIsNone(reader._observation)

    def physically_closed(self, reader, io, readers):
        self.assertFalse(io.live)
        self.assertTrue(all(row['closed'] for row in reader.original_resources))
        self.assertTrue(all(row['closed'] and row['reader'] is readers[index]
            for index, row in enumerate(reader.proc_readers)))
        for producer in readers:
            self.assertFalse(producer._pending)
            self.assertEqual(producer._files, producer._closed)
            for fs, fd in producer._fd_refs:
                with self.assertRaises(OSError) as caught:
                    fs.fstat(fd)
                self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_pure_ctor_and_strict_external_deadline_inputs(self):
        calls = []
        def callback(): calls.append('checkpoint'); return False
        def clock(): calls.append('clock'); return 100.0
        r, io, readers, _, _ = self.make(clock=clock, checkpoint=callback,
            deadline=101.0)
        self.assertEqual(calls, [])
        self.assertEqual(io.open_calls, [])
        self.assertEqual(readers, [])
        self.assertFalse(r.status()['attempted'])
        self.assertIsInstance(r.closed_receipts, tuple)
        for value in (True, False, 0, object()):
            with self.subTest(callback_type=type(value).__name__):
                with self.assertRaises(k.KernelReadError) as caught:
                    self.make(checkpoint=value)
                self.assertEqual(caught.exception.code, 'invalid_input')
        for value in (True, False, 0, -1, float('nan'), float('inf'),
                      10**1000, 1e12+1, '101'):
            with self.subTest(deadline_type=type(value).__name__):
                with self.assertRaises(k.KernelReadError) as caught:
                    self.make(deadline=value)
                self.assertEqual(caught.exception.code, 'invalid_input')
        self.assertEqual(calls, [])

    def test_fresh_real_reader_shared_min_deadline_and_original_receipts(self):
        for external, timeout, end, use_callback in (
                (None, 5.0, 105.0, False), (100.5, 5.0, 100.5, True),
                (110.0, 5.0, 105.0, True), (110.0, .5, 100.5, True)):
            with self.subTest(external=external, timeout=timeout):
                threads = []
                def checkpoint():
                    threads.append(threading.get_ident()); return False
                r, io, readers, owner, epoch = self.make(timeout=timeout,
                    deadline=external, checkpoint=checkpoint if use_callback else None)
                value = r.read()
                self.assertEqual(r._read_deadline, end)
                self.assertIsNone(r.authenticate(owner, int(str(epoch)), value))
                self.assertEqual(value.public_summary()['associated'], 'TRUE')
                self.assertEqual(set(value.private_fields()),
                    {'origin', 'executor', 'boot', 'channel', 'stations'})
                self.assertEqual(set(threads), {threading.get_ident()} if use_callback else set())
                self.assertTrue(r.status()['resources_closed'])
                self.assertFalse(r.status()['cancel_requested'])
                self.physically_closed(r, io, readers)
                receipts = r.closed_receipts
                self.assertIsInstance(receipts, tuple)
                for row in r.original_resources:
                    self.assertTrue(any(source is io and fd == row['fd'] and producer is row
                        for source, fd, producer in receipts))
                for reader in readers:
                    for fs, fd in reader._fd_refs:
                        self.assertTrue(any(source is fs and number == fd and producer is reader
                            for source, number, producer in receipts))
                self.assertEqual(len(receipts), len(r.original_resources)+
                    sum(len(x._fd_refs) for x in readers))
                self.assertEqual(io.raw.close_count, 1)
                # Historical issuance survives numeric reuse; this alone grants
                # no Provider/current live-generation authority.
                row = r.original_resources[0]
                io.live[row['fd']] = ['later', b'', 0, row['meta'][2]]
                self.assertIs(r.closed_receipts[-1][2], row)

    def test_true_nonbool_and_baseexception_cancel_sticky_before_io(self):
        callbacks = [(lambda value=value: value) for value in (True, None, 0, 1, 'False')]
        def exceptional(error):
            def callback(): raise error
            return callback
        callbacks += [exceptional(RuntimeError('private detail')),
                      exceptional(KeyboardInterrupt())]
        for callback in callbacks:
            with self.subTest():
                count = []
                def observed(): count.append(1); return callback()
                r, io, readers, _, _ = self.make(checkpoint=observed)
                self.rejected(r, 'cancelled')
                self.assertEqual(count, [1])
                self.assertEqual(readers, [])
                self.assertEqual(io.open_calls, [])
                self.assertTrue(r.status()['cancel_requested'])
                with self.assertRaises(k.KernelReadError) as caught: r.read()
                self.assertEqual(caught.exception.code, 'already_attempted')
                self.assertEqual(count, [1])

    def test_cancel_immediately_before_send_no_finally_poll_or_reclose(self):
        io = old.FakeIo(); flag = [False]; events = []
        settimeout = io.raw.settimeout
        def timeout(value): settimeout(value); flag[0] = True
        io.raw.settimeout = timeout
        close_socket, close_file = io.raw.close, io.close
        def socket_close(): events.append('close'); close_socket()
        def file_close(fd): events.append('close'); close_file(fd)
        io.raw.close, io.close = socket_close, file_close
        def checkpoint(): events.append('checkpoint'); return flag[0]
        r, io, readers, _, _ = self.make(io, checkpoint=checkpoint)
        self.rejected(r, 'cancelled')
        self.assertEqual(len(r.raw_requests), 1)
        self.assertEqual(io.raw.sent, [])
        self.assertEqual(io.raw.close_count, 1)
        self.assertNotIn('checkpoint', events[events.index('close'):])
        self.physically_closed(r, io, readers)
        with self.assertRaises(k.KernelReadError): r.read()
        self.assertEqual(io.raw.close_count, 1)

    def test_cancel_after_recv_retains_raw_unknown_ancillary_stays_pending(self):
        for ancillary in ([], [(1, 1, b'unknown')]):
            with self.subTest(has_ancillary=bool(ancillary)):
                io = old.FakeIo(); flag = [False]; received = []
                recvmsg = io.raw.recvmsg
                def receive(*args):
                    packet, _, flags, peer = recvmsg(*args)
                    value = (packet, ancillary, flags, peer)
                    received.append(value); flag[0] = True; return value
                io.raw.recvmsg = receive
                r, io, readers, _, _ = self.make(io, checkpoint=lambda: flag[0])
                self.rejected(r, 'receive_unknown' if ancillary else 'cancelled')
                self.assertEqual(len(r.raw_datagrams), 1)
                self.assertIs(r.raw_datagrams[0].data, received[0][0])
                self.assertIs(r.raw_datagrams[0].ancillary, ancillary)
                self.assertEqual(len(io.raw.sent), 1)
                self.assertEqual(r.status()['resource_pending'], bool(ancillary))
                self.assertEqual(r.status()['cancel_requested'], not bool(ancillary))
                self.physically_closed(r, io, readers)

    def test_cancel_after_original_proc_retains_exact_value_and_receipts(self):
        for target in (1, 2):
            with self.subTest(proc_round=target):
                flag = [False]; values = []
                def after(reader, value, round_number):
                    values.append(value)
                    if round_number == target: flag[0] = True
                r, io, readers, _, _ = self.make(checkpoint=lambda: flag[0], after_proc=after)
                self.rejected(r, 'cancelled')
                self.assertEqual(len(readers), target)
                self.assertTrue(r.status()['resources_closed'])
                self.physically_closed(r, io, readers)
                for row, value in zip(r.proc_readers, values):
                    self.assertIs(row['value'], value)
                    self.assertIs(type(value), old.proc.ProcObservation)
                    for fs, fd in row['reader']._fd_refs:
                        self.assertTrue(any(source is fs and original == fd and producer is row['reader']
                            for source, original, producer in r.closed_receipts))

    def test_external_absolute_boundary_after_proc_and_receipt_failure_pending(self):
        for final_time, accepted in ((100.499, True), (100.5, False), (100.501, False)):
            with self.subTest(final_time=final_time):
                now = [100.0]
                def after(reader, value, round_number):
                    if round_number == 2: now[0] = final_time
                r, io, readers, owner, epoch = self.make(deadline=100.5,
                    clock=lambda: now[0], checkpoint=lambda: False, after_proc=after)
                if accepted: self.assertIsNone(r.authenticate(owner, epoch, r.read()))
                else: self.rejected(r, 'deadline')
                self.assertEqual(r._read_deadline, 100.5)
                self.assertTrue(r.status()['resources_closed'])
                self.physically_closed(r, io, readers)
        class Unrecordable(list):
            def append(self, value): raise MemoryError('private registration failure')
        r, io, readers, _, _ = self.make(checkpoint=lambda: False)
        r._close_receipts = Unrecordable()
        self.rejected(r, 'resource_unknown')
        self.assertTrue(r.status()['receipt_unknown'])
        self.assertTrue(r.status()['resource_pending'])
        self.assertEqual(r.closed_receipts, ())
        self.physically_closed(r, io, readers)
        with self.assertRaises(k.KernelReadError): r.read()
        self.assertEqual(io.raw.close_count, 1)

    def test_python35_exact_baseline_and_unchanged_protocol_functions(self):
        before = BASELINE.read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(), BASELINE_SHA)
        original = ast.parse(before.decode('utf-8'), feature_version=(3, 5))
        current = ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        def functions(tree):
            result = {}
            for node in tree.body:
                if isinstance(node, ast.FunctionDef): result[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    for function in node.body:
                        if isinstance(function, ast.FunctionDef):
                            result[node.name+'.'+function.name] = function
            return result
        before_functions, after_functions = functions(original), functions(current)
        changed = {'ClientKernelReader.'+name for name in
            ('__init__', '_check', '_close', '_self', '_query', 'read', 'status')}
        for name, node in before_functions.items():
            if name not in changed:
                self.assertEqual(ast.dump(node), ast.dump(after_functions[name]), name)
        self.assertEqual(set(after_functions)-set(before_functions),
            {'ClientKernelReader.'+name for name in
             ('closed_receipts', '_checkpoint', '_budget', '_issue_closed')})
        forbidden = {'kill', 'waitpid', 'mkdir', 'unlink', 'system', 'Popen', 'write', 'flock'}
        calls = {node.func.attr for node in ast.walk(current)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & forbidden)


if __name__ == '__main__': unittest.main()
