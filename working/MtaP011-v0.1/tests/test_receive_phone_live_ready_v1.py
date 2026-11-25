"""HOST-only real pipe framing/timing; no target graph, ADB or radio executed."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'phone_live_host', BASE / 'host/device_receive_phone_discovery_v1_check.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class LivePipeTest(unittest.TestCase):
    def test_actual_pipe_ready_and_reject_invalid_frame(self):
        with tempfile.TemporaryDirectory(prefix='p011-phone-ready-host-') as folder:
            good = (b"print('PHONE_DISCOVERY_READY=source echo')\r\r\n" +
                b"ordinary output\r\r\nPHONE_DISCOVERY_READY=" +
                repr(host.READY_VALUE).encode('ascii') + b"\r\r\nend\r\r\n")
            # Actual child stdout, fragmented ready line, then delayed ordinary
            # output. Forwarding must happen while this child is still alive.
            first = good[:-6]
            program = ("import sys,time\n"
                "sys.stdout.buffer.write(" + repr(first[:80]) + ");sys.stdout.buffer.flush()\n"
                "time.sleep(.05)\n"
                "sys.stdout.buffer.write(" + repr(first[80:]) + ");sys.stdout.buffer.flush()\n"
                "time.sleep(.6)\n"
                "sys.stdout.buffer.write(b'end\\r\\r\\n');sys.stdout.buffer.flush()\n")
            child = subprocess.Popen([sys.executable, '-I', '-B', '-u', '-c', program],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ready, errors, forwarded = [], [], io.StringIO()
            raw_path = Path(folder) / 'good.raw'
            before = time.monotonic()
            with contextlib.redirect_stdout(forwarded):
                reader = threading.Thread(target=host.collect_ready_pipe,
                    args=(child.stdout, raw_path, True, ready, errors, child))
                reader.start()
                until = before + .5
                while not ready and time.monotonic() < until:
                    time.sleep(.01)
                before_exit = child.poll() is None
                ready_elapsed = time.monotonic() - before
                code = child.wait(timeout=3)
                reader.join(2)
            child.stderr.close()
            self.assertEqual(ready, [host.READY_VALUE])
            self.assertTrue(before_exit)
            self.assertLess(ready_elapsed, .5)
            self.assertEqual(code, 0)
            self.assertFalse(reader.is_alive())
            self.assertTrue(child.stdout.closed)
            self.assertEqual(errors, [])
            self.assertEqual(raw_path.read_bytes(), good)
            self.assertEqual(forwarded.getvalue(),
                             'PHONE_DISCOVERY_READY=' + repr(host.READY_VALUE) + '\n')
            bad = b"PHONE_DISCOVERY_READY={'ready':True}\r\r\n"
            program = ("import sys,time;sys.stdout.buffer.write(" + repr(bad) +
                       ");sys.stdout.buffer.flush();time.sleep(2)")
            child = subprocess.Popen([sys.executable, '-I', '-B', '-u', '-c', program],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ready, errors = [], []
            raw_path = Path(folder) / 'bad.raw'
            reader = threading.Thread(target=host.collect_ready_pipe,
                args=(child.stdout, raw_path, True, ready, errors, child))
            reader.start()
            child.wait(timeout=3)
            reader.join(2)
            child.stderr.close()
            self.assertFalse(reader.is_alive())
            self.assertTrue(child.stdout.closed)
            self.assertEqual(ready, [])
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertEqual(raw_path.read_bytes(), bad)


if __name__ == '__main__':
    unittest.main(verbosity=2)
