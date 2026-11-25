"""Focused PC tests of the new FileCenter absolute cleanup budget.

Actual loopback HTTP sockets, files, locks, threads and one Linux audio child
are used. Owner/directory authority and gst playback are not P011 acceptance.
The blocked HTTP handler and blocked audio reader are named HOST fixtures;
the gst launcher seam substitutes only a real bounded Python process argv.
"""
import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0, str(ROOT/'candidate/receive-filecenter-v1/runtime'))
sys.path.insert(0, str(ROOT/'candidate/filecenter-deadline-v1/runtime'))
import mta_filecenter_companion as C
import mta_filecenter_audio as A


class FileCenterDeadlineTests(unittest.TestCase):
    def start(self, root):
        return C._Companion(str(root), float(time.monotonic()+30), lambda:True)

    def test_normal_http_media_and_close(self):
        with tempfile.TemporaryDirectory(prefix='p011-fc-deadline-') as temporary:
            value = self.start(Path(temporary))
            try:
                source = Path(temporary)/'Received'/'image.png'
                source.write_bytes(b'HOST image bytes')
                opened = value.open_file('Received/image.png')
                with urllib.request.urlopen(opened['url'], timeout=2) as response:
                    self.assertEqual(response.read(), b'HOST image bytes')
                self.assertTrue(value.close(cleanup_until=float(time.monotonic()+1)))
                self.assertTrue(value.closed())
                self.assertFalse(value.thread.is_alive())
                self.assertEqual(value.socket_original.fileno(), -1)
                self.assertTrue(value.state.store.opens_closed())
                self.assertTrue(value.media[0]['handle'].closed)
            finally:
                if not value.close_called: value.close()

    def test_blocked_http_wait_is_clipped_and_pending_not_renewed(self):
        entered, release = threading.Event(), threading.Event()
        clients = []
        class BlockedHostHandler(C._FileCenterHandler):
            def dispatch(self):
                entered.set()
                release.wait(3)
        with tempfile.TemporaryDirectory(prefix='p011-fc-http-budget-') as temporary:
            value = self.start(Path(temporary))
            value.server.handler = BlockedHostHandler
            def client():
                try:
                    urllib.request.urlopen('http://'+value.server.expected_host+'/api/state', timeout=3).close()
                except Exception: pass
            worker = threading.Thread(target=client)
            clients.append(worker); worker.start()
            try:
                self.assertTrue(entered.wait(1))
                deadline = float(time.monotonic()+0.08)
                start = time.monotonic()
                self.assertFalse(value.close(cleanup_until=deadline))
                self.assertLess(time.monotonic()-start, 0.35)
                self.assertLessEqual(value.cleanup_until, deadline)
                self.assertFalse(value.closed())
                self.assertFalse(value.server.actors_closed())
                retained = tuple(value.server.actor_rows)
                self.assertTrue(retained)
                self.assertTrue(any(row['thread'].is_alive() for row in retained if row['thread'] is not None))
                original_cap = value.cleanup_until
                self.assertFalse(value.close(cleanup_until=float(time.monotonic()+10)))
                self.assertEqual(value.cleanup_until, original_cap)
            finally:
                # The HOST fixture releases its own blocked handler after the
                # product returned pending; this is not a product close receipt.
                release.set()
                for worker in clients: worker.join(2)
                value.thread.join(2)
                for row in value.server.actor_rows:
                    if row['thread'] is not None: row['thread'].join(2)
                value.state.store.close_known_opens()

    def test_audio_control_lock_wait_is_clipped(self):
        held, release = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory(prefix='p011-fc-lock-budget-') as temporary:
            value = self.start(Path(temporary))
            def holder():
                with value.state.audio_control_lock:
                    held.set(); release.wait(3)
            worker = threading.Thread(target=holder); worker.start()
            try:
                self.assertTrue(held.wait(1))
                deadline = float(time.monotonic()+0.08)
                start = time.monotonic()
                self.assertFalse(value.close(cleanup_until=deadline))
                self.assertLess(time.monotonic()-start, 0.35)
                self.assertTrue(any(str(error)=='filecenter_audio_control_pending' for error in value.cleanup_failures))
                self.assertFalse(value.closed())
            finally:
                release.set(); worker.join(2); value.thread.join(2)

    def test_audio_reader_timeout_keeps_original_fields(self):
        release = threading.Event()
        with tempfile.TemporaryDirectory(prefix='p011-fc-reader-budget-') as temporary:
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0)
            reader = threading.Thread(target=lambda:release.wait(3)); reader.start()
            stop = threading.Event()
            ticket = dict(process=None, reader=reader, stop=stop, streams=[],
                reader_initialized=True, start_called=True, start_returned=True,
                spawn_called=False, spawn_returned=False)
            value.tickets.append(ticket)
            value.audio_reader = reader; value.audio_reader_stop = stop
            try:
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '音频读取线程尚未停止'):
                    value.stop_audio(cleanup_until=float(time.monotonic()+0.05))
                self.assertLess(time.monotonic()-start, 0.25)
                self.assertIs(value.audio_reader, reader)
                self.assertIs(value.audio_reader_stop, stop)
                self.assertIs(value.tickets[0], ticket)
                self.assertFalse(value.actors_closed())
            finally:
                release.set(); reader.join(2)
                value.stop_audio(cleanup_until=float(time.monotonic()+0.5))
            self.assertTrue(value.actors_closed())

    @unittest.skipUnless(os.name=='posix', 'gst reader uses select on POSIX pipe FDs')
    def test_real_audio_child_stop_and_stream_close(self):
        with tempfile.TemporaryDirectory(prefix='p011-fc-audio-budget-') as temporary:
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0)
            original_popen = subprocess.Popen
            def host_child(command, **kwargs):
                self.assertIn('gst-play-1.0', command[0])
                return original_popen([sys.executable, '-c',
                    "import time;print('0:00:00.100 / 0:00:30.000',flush=True);time.sleep(30)"], **kwargs)
            try:
                with mock.patch.object(A.os.path, 'isfile', return_value=True), \
                        mock.patch.object(A.subprocess, 'Popen', side_effect=host_child):
                    value.play('HOST source', 25)
                ticket = value.tickets[0]
                self.assertIsNotNone(ticket['process'])
                self.assertTrue(ticket['reader'].is_alive())
                start = time.monotonic()
                value.stop_audio(cleanup_until=float(time.monotonic()+0.5))
                self.assertLess(time.monotonic()-start, 0.7)
                self.assertIsNotNone(ticket['process'].poll())
                self.assertFalse(ticket['reader'].is_alive())
                self.assertTrue(all(stream.closed for stream in ticket['streams']))
                self.assertTrue(value.actors_closed())
            finally:
                if value.audio is not None:
                    value.stop_audio(cleanup_until=float(time.monotonic()+1))

    @unittest.skipUnless(os.name=='posix', 'real SIGTERM-ignore fixture is POSIX-only')
    def test_process_escalation_uses_same_remaining_budget(self):
        release = threading.Event()
        with tempfile.TemporaryDirectory(prefix='p011-fc-process-budget-') as temporary:
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0)
            proc = subprocess.Popen([sys.executable, '-c',
                "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(30)"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reader = threading.Thread(target=lambda:release.wait(3))
            stop = threading.Event()
            ticket = dict(process=proc, reader=reader, stop=stop,
                streams=[proc.stdout, proc.stderr], reader_initialized=True,
                start_called=True, start_returned=True, spawn_called=True, spawn_returned=True)
            value.tickets.append(ticket)
            value.audio = proc; value.audio_reader = reader; value.audio_reader_stop = stop
            try:
                self.assertEqual(proc.stdout.readline(), b'READY\n')
                reader.start()
                start = time.monotonic()
                with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                    value.stop_audio(cleanup_until=float(time.monotonic()+0.08))
                self.assertLess(time.monotonic()-start, 0.35)
                self.assertIs(value.audio, proc)
                self.assertIs(value.audio_reader, reader)
                self.assertFalse(value.actors_closed())
            finally:
                release.set()
                if reader.ident is not None: reader.join(2)
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=2)
                value.stop_audio(cleanup_until=float(time.monotonic()+0.5))
            self.assertTrue(value.actors_closed())

    def test_modified_sources_parse_as_python35(self):
        for name in ('mta_filecenter_companion.py', 'mta_filecenter_audio.py', 'mta_client_service_owner.py'):
            raw = (ROOT/'candidate/filecenter-deadline-v1/runtime'/name).read_bytes()
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))

    def test_owner_pins_point_at_actual_new_components(self):
        folder = ROOT/'candidate/filecenter-deadline-v1/runtime'
        tree = ast.parse((folder/'mta_client_service_owner.py').read_text(encoding='utf-8'))
        pins = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id=='FILECENTER_PINS' for target in node.targets)))
        for name in ('mta_filecenter_audio', 'mta_filecenter_companion'):
            raw = (folder/(name+'.py')).read_bytes()
            row = next(row for row in pins if row[0]==name)
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), row[1:])


if __name__=='__main__': unittest.main(verbosity=2)
