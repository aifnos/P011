"""Affected v2 checks only: bounded cleanup/query locks and startup rollback.

Real HTTP servers, locks, threads and POSIX Python children are exercised.
The gst argv seam and Thread constructor/start failures are explicitly HOST
fault fixtures. No guardian, radio, full Owner graph or P011 is exercised.
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

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT/'candidate/filecenter-deadline-v2/runtime'
sys.path.insert(0, str(ROOT/'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0, str(ROOT/'candidate/receive-filecenter-v1/runtime'))
sys.path.insert(0, str(FOLDER))
import mta_filecenter_companion as C
import mta_filecenter_audio as A


class FileCenterDeadlineV2Tests(unittest.TestCase):
    def hold(self, lock):
        entered, release = threading.Event(), threading.Event()
        def holder():
            with lock: entered.set(); release.wait(3)
        worker = threading.Thread(target=holder); worker.start()
        self.assertTrue(entered.wait(1))
        return release, worker

    def test_held_server_locks_return_pending_without_blocking_closed(self):
        for label in ('worker', 'actor'):
            with self.subTest(lock=label), tempfile.TemporaryDirectory(prefix='p011-fc-v2-lock-') as temporary:
                value = C._Companion(temporary, float(time.monotonic()+20), lambda:True)
                lock = value.server.worker_lock if label=='worker' else value.server.actor_lock
                release, holder = self.hold(lock)
                try:
                    cap = float(time.monotonic()+0.08)
                    started = time.monotonic()
                    self.assertFalse(value.close(cleanup_until=cap))
                    elapsed = time.monotonic()-started
                    self.assertLess(elapsed, 0.35)
                    self.assertTrue(any(str(error)=='filecenter_http_'+label+'_lock_pending'
                        for error in value.cleanup_failures))
                    started = time.monotonic()
                    self.assertFalse(value.closed())
                    self.assertLess(time.monotonic()-started, 0.05)
                    self.assertIs(value.server.worker_lock if label=='worker' else value.server.actor_lock, lock)
                    print('HOST_V2_HELD_%s_LOCK_SECONDS=%.6f' % (label.upper(), elapsed))
                finally:
                    release.set(); holder.join(2); value.thread.join(2)
                    value.state.store.close_known_opens()

    def test_held_audio_lock_bounds_stop_snapshot_and_passive_close(self):
        with tempfile.TemporaryDirectory(prefix='p011-fc-v2-audio-lock-') as temporary:
            cap = float(time.monotonic()+0.12)
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0, parent_until=cap)
            release, holder = self.hold(value.lock)
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, 'audio_state_lock_pending'):
                    value.stop_audio(cleanup_until=cap)
                elapsed = time.monotonic()-started
                self.assertLess(elapsed, 0.35)
                self.assertTrue(value.cleanup_pending)
                started = time.monotonic()
                self.assertFalse(value.actors_closed())
                with self.assertRaisesRegex(RuntimeError, 'audio_state_lock_pending'):
                    value.audio_snapshot()
                self.assertLess(time.monotonic()-started, 0.05)
                self.assertIs(value.parent_until, cap)
                self.assertIs(value._parent_until_original, cap)
                print('HOST_V2_HELD_AUDIO_LOCK_SECONDS=%.6f' % elapsed)
            finally:
                release.set(); holder.join(2)
                value.stop_audio(cleanup_until=float(time.monotonic()+0.5))
            self.assertTrue(value.actors_closed())

    def test_companion_binds_original_audio_parent_and_normal_close(self):
        with tempfile.TemporaryDirectory(prefix='p011-fc-v2-binding-') as temporary:
            cap = float(time.monotonic()+20)
            value = C._Companion(temporary, cap, lambda:True)
            try:
                self.assertIs(value.audio.parent_until, cap)
                self.assertIs(value.audio._parent_until_original, cap)
                self.assertEqual(value.audio.audio_snapshot()['status'], 'stopped')
                self.assertTrue(value.close(cleanup_until=float(time.monotonic()+1)))
                self.assertTrue(value.closed())
            finally:
                if not value.close_called: value.close()

    def test_audio_pending_queries_cannot_renew_failed_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='p011-fc-v2-query-budget-') as temporary:
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0)
            release, holder = self.hold(value.lock)
            cap = float(time.monotonic()+0.05)
            try:
                with self.assertRaisesRegex(RuntimeError, 'audio_state_lock_pending'):
                    value.stop_audio(cleanup_until=cap)
                saved_cap = value.cleanup_until
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, 'audio_state_lock_pending'): value.audio_snapshot()
                with self.assertRaisesRegex(RuntimeError, 'audio_state_lock_pending'):
                    value.stop_audio(cleanup_until=float(time.monotonic()+3))
                self.assertFalse(value.actors_closed())
                self.assertLess(time.monotonic()-started, 0.05)
                self.assertLessEqual(value.cleanup_until, saved_cap)
                print('HOST_V2_PENDING_QUERY_AND_RETRY_SECONDS=%.6f' % (time.monotonic()-started))
            finally:
                release.set(); holder.join(2)
                value.stop_audio(cleanup_until=float(time.monotonic()+0.5))
            self.assertTrue(value.actors_closed())

    def startup_fault(self, phase):
        with tempfile.TemporaryDirectory(prefix='p011-fc-v2-start-fault-') as temporary:
            cap = float(time.monotonic()+0.2)
            value = A.FileCenterAudio(temporary, lambda event:None, lambda path:0, parent_until=cap)
            actual_popen, actual_start = subprocess.Popen, threading.Thread.start
            marker = RuntimeError('HOST injected reader '+phase+' outcome')
            def child(command, **kwargs):
                self.assertIn('gst-play-1.0', command[0])
                proc = actual_popen([sys.executable, '-c',
                    "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(30)"], **kwargs)
                self.assertEqual(proc.stdout.readline(), b'READY\n')
                return proc
            def start_then_unknown(reader):
                actual_start(reader)
                raise marker
            fault = mock.patch.object(A.threading.Thread, '__init__', side_effect=marker) if phase=='init' else \
                mock.patch.object(A.threading.Thread, 'start', start_then_unknown)
            try:
                started = time.monotonic()
                with mock.patch.object(A.os.path, 'isfile', return_value=True), \
                        mock.patch.object(A.subprocess, 'Popen', side_effect=child), fault:
                    with self.assertRaises(RuntimeError) as caught: value.play('HOST source', 25)
                elapsed = time.monotonic()-started
                self.assertIs(caught.exception, marker)
                self.assertLess(elapsed, 0.65)
                ticket = value.tickets[0]
                self.assertIs(ticket['failure'], marker)
                self.assertIsNotNone(ticket['cleanup_failure'])
                self.assertIs(value.audio, ticket['process'])
                self.assertIs(value.audio_reader, ticket['reader'])
                self.assertFalse(value.actors_closed())
                self.assertTrue(value.cleanup_pending)
                print('HOST_V2_STARTUP_%s_SECONDS=%.6f' % (phase.upper(), elapsed))
            finally:
                # Only the HOST fixture closes its own known actual child and
                # streams after the product returned pending. No product grant.
                for ticket in value.tickets:
                    proc = ticket['process']; reader = ticket['reader']
                    if ticket['stop'] is not None: ticket['stop'].set()
                    if proc is not None:
                        if proc.poll() is None: proc.kill()
                        proc.wait(timeout=2)
                    if phase=='start' and reader is not None and reader.ident is not None: reader.join(2)
                    for stream in ticket['streams']: stream.close()
                self.assertFalse(value.actors_closed())

    @unittest.skipUnless(os.name=='posix', 'actual SIGTERM-ignore child is POSIX-only')
    def test_reader_constructor_failure_cannot_renew_parent_deadline(self):
        self.startup_fault('init')

    @unittest.skipUnless(os.name=='posix', 'actual pipe reader and SIGTERM-ignore child are POSIX-only')
    def test_started_reader_exception_cannot_renew_parent_deadline(self):
        self.startup_fault('start')

    def test_new_sources_parse_python35_and_owner_pins_match(self):
        trees = {}
        for name in ('mta_filecenter_audio', 'mta_filecenter_companion', 'mta_client_service_owner'):
            trees[name] = ast.parse((FOLDER/(name+'.py')).read_text(encoding='utf-8'), feature_version=(3, 5))
        pins = ast.literal_eval(next(node.value for node in trees['mta_client_service_owner'].body
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id=='FILECENTER_PINS'
                for target in node.targets)))
        for name in ('mta_filecenter_audio', 'mta_filecenter_companion'):
            raw = (FOLDER/(name+'.py')).read_bytes()
            pin = next(row for row in pins if row[0]==name)
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), pin[1:])


if __name__=='__main__': unittest.main(verbosity=2)
