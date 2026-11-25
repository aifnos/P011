"""NEW HOST producer fstat vs close EBADF boundary; not a full syscall cap."""
from contextlib import ExitStack
import hashlib
import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SCOPED_SHA = '2852349973865d3a2b09bbd4ac51862d651429a1e31bbcb363e125669b0a61b4'
path = BASE / 'tests/test_client_proc_absolute_deadline_v25.py'
if hashlib.sha256(path.read_bytes()).hexdigest() != SCOPED_SHA:
    raise ValueError('frozen definition drift')
sys.path.insert(0, str(BASE / 'tests'))
definitions = importlib.import_module('test_client_proc_absolute_deadline_v25')


class ProcMetadataDeadlineV25Tests(unittest.TestCase):
    def test_late_open_eof_and_metadata_return_stop_producer_fstat_but_close_original_once(self):
        with ExitStack() as stack:
            for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
                    'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat',
                    'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid', 'os.fork',
                    'os.execve', 'os.kill', 'os.waitpid', 'os.system',
                    'threading.Thread.start', 'time.sleep'):
                stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))
            modules = definitions.domain()
            proc, stores, core = (modules[name] for name in
                ('mta_client_proc', 'mta_client_store', 'mta_p2p_client_init'))
            for mode in ('open', 'eof', 'metadata'):
                with self.subTest(mode=mode):
                    clock, fs = definitions.Clock(), definitions.definitions.fs_fixture.FakeFs()
                    store = stores.DurableClientInitStore(definitions.definitions.fixture.old.TOKEN,
                        core.Identity(definitions.definitions.fixture.IDENTITY.candidate_sha), _clock=clock)
                    reader = proc.ProcReader(_fs=fs, _clock=clock)
                    store._resource_budget_v23.bind_reader(reader)
                    events, crossed = [], [False]
                    def returns_late(unused, operation, path, count):
                        events.append((operation, clock()))
                        match = (mode == 'open' and operation == 'open' or
                            mode == 'eof' and operation == 'read' and count == 2 or
                            mode == 'metadata' and operation == 'fstat')
                        if match and not crossed[0]: crossed[0] = True; clock.value = 1.201
                    fs.hook = returns_late
                    value = reader.read_self(_absolute_deadline=1.2)
                    self.assertEqual(('unknown', 'deadline'), (value.kind, value.reason))
                    self.assertTrue(crossed[0])
                    # FakeFs only emits fstat for a LIVE fd. The immediate
                    # close-readback EBADF has no producer event, so this
                    # assertion includes every normal metadata fstat.
                    self.assertFalse([(op, when) for op, when in events if when >= 1.2])
                    generation = reader.operation_history[-1]
                    self.assertEqual(1, len(generation.tickets))
                    ticket = generation.tickets[0]
                    self.assertTrue(reader.closed_open_ticket(ticket))
                    self.assertTrue(ticket.close_attempted and ticket.close_returned and ticket.ebadf_observed)
                    self.assertEqual([ticket.descriptor], fs.closed)
                    self.assertFalse(fs.live); self.assertEqual(value.file_count, value.closed_count)
                    self.assertTrue(reader.history_closed())
                    self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])


if __name__ == '__main__': unittest.main()
