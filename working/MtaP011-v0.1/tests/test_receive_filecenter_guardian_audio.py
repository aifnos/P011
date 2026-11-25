"""One new HOST guardian/Audio method, not the four historical methods.

Actual frozen definitions, tempfile logs, pipe metadata, threads and RLock run.
Popen, target /proc, target signals, ACK transport and guardian native IO are
explicit HOST doubles. No real signal, fork, gst, P011, Owner or radio runs.
Source AST checks identify production terminal/credential call sites; they
do not turn those unexecuted native call sites into hardware acceptance.
"""
import ast
from contextlib import ExitStack
import hashlib
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT/'candidate/receive-filecenter-v1/runtime'
sys.path.insert(0, str(ROOT/'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0, str(RUNTIME))
import mta_filecenter_audio as A

UI_SOURCE = (RUNTIME/'ui_session.py').read_text(encoding='utf-8')
U = types.ModuleType('fixed_host_guardian_audio_source')
U.__file__ = str(RUNTIME/'ui_session.py')
exec(compile(UI_SOURCE, U.__file__, 'exec'), U.__dict__)


class Context:
    """No target actor: actual host FD/thread objects plus explicit proc model."""
    def __init__(self, folder):
        self.folder = folder
        self.events, self.queue, self.rows, self.signals = [], [], [], []
        self.pid_next = 970000
        self.worker = dict(pid=os.getpid(), start='100', parent=1, sid=os.getpid(),
            exe='HOST_FIXED_WORKER', args=('HOST_FIXED_WORKER',), state='R', threads=1)
        self.guardian = dict(pid=960000, start='101', parent=self.worker['pid'],
            sid=960000, exe='HOST_FIXED_WORKER', args=('HOST_GUARDIAN',), state='R', threads=1)
        self.actors = {self.worker['pid']: self.worker, self.guardian['pid']: self.guardian}
        self.boot = '00000000-0000-0000-0000-000000000001'
        self.until = float(time.monotonic()+40)
        self.component = types.SimpleNamespace(until=self.until, cleanup_until=self.until+60.0,
            owner=types.SimpleNamespace(clock=time.monotonic), rows=[])
        self.fds = list(os.pipe()) + list(os.pipe())
        for fd in self.fds:
            meta = os.fstat(fd)
            self.component.rows.append(dict(fd=fd, metadata=(meta.st_dev, meta.st_ino,
                meta.st_mode, meta.st_uid, meta.st_gid, meta.st_nlink), closed=False, unknown=False))
        self.write_fd, self.read_fd = self.fds[1], self.fds[2]
        self.guard_write_fd = self.fds[3]
        self.release_read = self.read_waiting = None
        self.bad_ack = False
        self.fail_spawn = False
        self.source_calls = []
        self.fd_changed = False
        self.audio = A.FileCenterAudio(str(folder), lambda value: None, self.source_fd)
        self.companion = types.SimpleNamespace(audio=self.audio,
            state=types.SimpleNamespace(audio=self.audio))
        self.channel = U._FileCenterGuardianChannel(self.component,
            self.component.rows[1], self.component.rows[2], b'', dict(boot=self.boot),
            self.worker, self.guardian, [False])
        context = self
        class ProcessModel:
            def __init__(self, argv, **kwargs):
                context.events.append('spawn')
                if context.fail_spawn:
                    raise OSError('HOST unknown Popen return')
                context.pid_next += 1
                self.pid, self.args, self.code = context.pid_next, argv, None
                self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
                context.actors[self.pid] = dict(pid=self.pid, start=str(self.pid),
                    parent=context.worker['pid'], sid=context.worker['sid'],
                    exe=context.worker['exe'], args=tuple(argv), state='T', threads=1)
            def poll(self): return self.code
            def send_signal(self, number):
                context.events.append('resume')
                context.actors[self.pid]['state'] = 'R'
                context.actors[self.pid]['exe'] = '/usr/bin/gst-play-1.0'
                context.actors[self.pid]['args'] = tuple(self.args[3:])
            def terminate(self): self.code = -15
            def kill(self): self.code = -9
            def wait(self, timeout=None):
                if self.code is None: self.code = 0
                return self.code
        self.ProcessModel = ProcessModel

    def source_fd(self, path):
        self.source_calls.append(path)
        return 72 if self.fd_changed and len(self.source_calls)>1 else 71

    def native_proc(self, pid):
        value = self.actors.get(pid)
        return None if value is None else dict(value)

    def write(self, fd, message):
        frame = message.rstrip('\n')
        if fd == self.write_fd:
            self.events.append(frame.split(' ')[0])
            U._guardian_audio_frame(frame, self.rows, self.worker, dict(boot=self.boot),
                self.guard_write_fd, False)
        elif fd == self.guard_write_fd:
            self.events.append(frame.split(' ')[0])
            self.queue.append('HOST_BAD_ACK' if self.bad_ack and frame.startswith('AUDIO_ACK ') else frame)
        else:
            raise AssertionError('HOST unexpected pipe FD')

    def read(self, fd, pending):
        if self.release_read is not None and not self.release_read.is_set():
            self.read_waiting.set()
            self.release_read.wait(timeout=1)
        if self.queue:
            return b'', (self.queue.pop(0),), False
        return pending, (), False

    def reader(self, audio, proc, generation, stopped, stdout, stderr):
        proc.code = 0
        self.actors.pop(proc.pid, None)
        for value in (proc.stdout, proc.stderr, stdout, stderr): value.close()

    def patches(self):
        stack = ExitStack()
        original_stat, original_isfile, original_realpath = os.stat, os.path.isfile, os.path.realpath
        program_meta = types.SimpleNamespace(st_dev=1, st_ino=9,
            st_mode=U.stat.S_IFREG|0o755, st_uid=0, st_gid=0)
        stack.enter_context(mock.patch.object(U, '_boot', return_value=self.boot))
        stack.enter_context(mock.patch.object(U, '_proc', side_effect=self.native_proc))
        stack.enter_context(mock.patch.object(U, '_pipe_write', side_effect=self.write))
        stack.enter_context(mock.patch.object(U, '_pipe_read', side_effect=self.read))
        stack.enter_context(mock.patch.object(U.subprocess, 'Popen', self.ProcessModel))
        stack.enter_context(mock.patch.object(os.path, 'realpath', side_effect=lambda p, *a, **k:
            p if p in U.AUDIO_PROGRAMS else original_realpath(p, *a, **k)))
        stack.enter_context(mock.patch.object(os.path, 'isfile', side_effect=lambda p:
            True if p in U.AUDIO_PROGRAMS else original_isfile(p)))
        stack.enter_context(mock.patch.object(os, 'stat', side_effect=lambda p, *a, **k:
            program_meta if p in U.AUDIO_PROGRAMS else original_stat(p, *a, **k)))
        stack.enter_context(mock.patch.object(signal, 'SIGCONT', 18, create=True))
        stack.enter_context(mock.patch.object(A.FileCenterAudio, 'read_audio',
            lambda audio, *args: self.reader(audio, *args)))
        self.channel.bind(self.audio, A, self.companion)
        return stack

    def close(self):
        if self.audio.audio_reader is not None:
            self.audio.audio_reader.join(timeout=1)
        self.audio.stop_audio()
        for ticket in self.audio.tickets:
            for stream in ticket['streams']:
                if not stream.closed: stream.close()
        for fd in self.fds: os.close(fd)


class GuardianAudioTests(unittest.TestCase):
    def test_new_guardian_audio_contracts(self):
        cases = []
        tree = ast.parse(UI_SOURCE)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        run_source = ast.get_source_segment(UI_SOURCE, functions['run_fixed'])
        guard_source = ast.get_source_segment(UI_SOURCE, functions['_guardian'])
        audio_raw = (RUNTIME/'mta_filecenter_audio.py').read_bytes()
        audio_pin = next(row for row in U.FILECENTER_PINS if row[0]=='mta_filecenter_audio')
        self.assertEqual((len(audio_raw),hashlib.sha256(audio_raw).hexdigest()),audio_pin[1:])
        self.assertEqual(32,U.AUDIO_MAX);self.assertEqual(2.0,U.AUDIO_ACK_SECONDS)
        self.assertEqual(A.GUARDIAN_WRAPPER,U.AUDIO_WRAPPER)
        self.assertIn('recover_at = component.until + 68.0',guard_source)
        self.assertIn('end = component.until + 135.0',guard_source)
        self.assertLess(run_source.index("need(_filecenter_current(component, ticket)"),
                        run_source.index("ticket['credentials_issued'] = True"))
        self.assertIn('with channel_lock:',run_source)
        self.assertLess(run_source.index('guardian_channel.terminal = True'),
                        run_source.index("_pipe_write(write_fd, 'OWNER_CLOSED_REPORTED"))
        self.assertLess(guard_source.index('if recovery_failures:'),
                        guard_source.index("_signal(baseline['launcher'], signal.SIGCONT"))
        cases.append('source_pins_caps_credentials_terminal_and_restore_call_sites')

        with tempfile.TemporaryDirectory(prefix='p011-guardian-audio-host-') as temporary:
            root = Path(temporary)
            def context(name):
                folder=root/name;folder.mkdir()
                return Context(folder)
            c=context('worker')
            try:
                errors=[]
                def other_worker():
                    try: c.channel.bind(c.audio,A,c.companion)
                    except U.UiSessionError as error: errors.append(error.code)
                thread=threading.Thread(target=other_worker);thread.start();thread.join(timeout=1)
                self.assertFalse(thread.is_alive());self.assertEqual(['audio_guardian_source'],errors)
                self.assertFalse(c.channel.bound);self.assertIsNone(c.audio._guardian_original)
                with c.patches():
                    errors.clear()
                    def other_stop():
                        try: c.channel.prevent_new()
                        except U.UiSessionError as error: errors.append(error.code)
                    thread=threading.Thread(target=other_stop);thread.start();thread.join(timeout=1)
                    self.assertEqual(['audio_guardian_source'],errors);self.assertFalse(c.channel.closing)
            finally:c.close()
            cases.append('original_bind_and_prevent_new_same_worker_gate')

            c=context('roundtrip')
            try:
                with c.patches():
                    c.audio.play('HOST_AUDIO_PATH',25)
                    c.audio.audio_reader.join(timeout=1)
                    self.assertEqual(['AUDIO_PREPARE','AUDIO_PREPARED','spawn','AUDIO','AUDIO_ACK','resume'],c.events)
                    ticket=c.audio.tickets[0];row=c.rows[0]
                    self.assertTrue(ticket['guardian_registered']);self.assertTrue(ticket['resume_returned'])
                    self.assertTrue(row['register_ack_returned']);self.assertEqual(2,len(c.source_calls))
                    self.assertTrue(c.audio.actors_closed());c.channel.prevent_new()
                    self.assertTrue(c.channel.settled())
            finally:c.close()
            cases.append('actual_original_order_prepare_register_ack_resume_and_retained_stream_close')

            c=context('badack');c.bad_ack=True
            try:
                with c.patches():
                    with self.assertRaises(U.UiSessionError) as caught:c.audio.play('HOST_AUDIO_PATH')
                    self.assertEqual('audio_guardian_ack',caught.exception.code)
                    self.assertNotIn('resume',c.events);self.assertFalse(c.audio.tickets[0]['resume_called'])
                    self.assertTrue(c.rows[0]['registered']);c.channel.prevent_new()
                    self.assertFalse(c.channel.settled())
            finally:c.close()
            cases.append('failed_ack_never_resumes_or_signs_normal_close')

            c=context('fd');c.fd_changed=True
            try:
                with c.patches():
                    with self.assertRaises(ValueError):c.audio.play('HOST_AUDIO_PATH')
                    self.assertIn('AUDIO_ACK',c.events);self.assertNotIn('resume',c.events)
                    self.assertFalse(c.audio.tickets[0]['resume_called'])
            finally:c.close()
            cases.append('post_ack_original_media_fd_revalidation_before_resume')

            c=context('unknown');c.fail_spawn=True
            try:
                with c.patches():
                    with self.assertRaises(OSError):c.audio.play('HOST_AUDIO_PATH')
                    self.assertNotIn('AUDIO',c.events);self.assertNotIn('resume',c.events)
                    self.assertIsNone(c.rows[0]['actor']);self.assertFalse(c.audio.actors_closed())
                    c.channel.prevent_new();self.assertFalse(c.channel.settled())
            finally:c.close()
            cases.append('unknown_popen_return_keeps_intent_without_resume_or_close_claim')

            # Native guardian preparation is an explicit IO/process model.
            # Real os.dup2, setsid, kill, fork and target /proc are never called.
            c=context('restore');frames=[('AUDIO_PREPARE 1 71 0 25',)]
            writes=[];signals=[];exit_codes=[]
            try:
                with c.patches(), ExitStack() as stack:
                    meta=types.SimpleNamespace(st_dev=1,st_ino=2)
                    stack.enter_context(mock.patch.object(U.os,'setsid',create=True))
                    stack.enter_context(mock.patch.object(U.os,'open',return_value=99))
                    stack.enter_context(mock.patch.object(U.os,'dup2'))
                    stack.enter_context(mock.patch.object(U.os,'fstat',return_value=meta))
                    stack.enter_context(mock.patch.object(U.signal,'signal'))
                    for name,number in (('SIGHUP',1),('SIGALRM',14),('SIGSTOP',19)):
                        stack.enter_context(mock.patch.object(U.signal,name,number,create=True))
                    stack.enter_context(mock.patch.object(U,'_child_close'))
                    stack.enter_context(mock.patch.object(U,'_guardian_fd_gate'))
                    stack.enter_context(mock.patch.object(U,'_scan',return_value=[]))
                    stack.enter_context(mock.patch.object(U,'_signal',side_effect=lambda *args:signals.append(args)))
                    stack.enter_context(mock.patch.object(U,'_pipe_write',side_effect=lambda fd,msg:writes.append(msg)))
                    stack.enter_context(mock.patch.object(U,'_pipe_read',side_effect=lambda fd,pending:
                        (b'',frames.pop(0),True) if frames else (b'',(),True)))
                    def exited(code):exit_codes.append(code);raise SystemExit(code)
                    stack.enter_context(mock.patch.object(U.os,'_exit',side_effect=exited))
                    component=types.SimpleNamespace(until=c.until,rows=[])
                    with self.assertRaises(SystemExit):
                        U._guardian(component,1,2,({'fd':3},{'fd':4}),
                            dict(boot=c.boot,launcher=c.worker),c.worker)
                self.assertEqual([2],exit_codes);self.assertEqual([],signals)
                self.assertNotIn('RESTORED\n',writes)
            finally:c.close()
            cases.append('unknown_registration_guardian_never_resumes_launcher_or_sends_restored')

            c=context('deadline')
            try:
                with c.patches():
                    U._guardian_audio_frame('AUDIO_PREPARE 1 71 0 25',c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                    row=c.rows[0];actor=dict(c.worker,pid=980001,start='901',parent=c.worker['pid'],state='R')
                    actor['args']=row['wrapper'];c.actors[actor['pid']]=actor
                    row.update(actor=dict(actor),registered=True)
                    with mock.patch.object(U.time,'monotonic',side_effect=[0.0,2.0]), \
                         mock.patch.object(U.os,'kill') as kill:
                        with self.assertRaises(U.UiSessionError):U._guardian_stop_audio(c.rows,c.worker,c.boot,1.0)
                    kill.assert_not_called();self.assertFalse(row['term_called'])
            finally:c.close()
            cases.append('term_neighbor_deadline_rejects_signal_after_expiry')

            c=context('known')
            try:
                with c.patches():
                    for number in (1,2):
                        U._guardian_audio_frame('AUDIO_PREPARE %d 71 0 25'%number,c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                        row=c.rows[-1];actor=dict(c.worker,pid=980010+number,start=str(910+number),parent=c.worker['pid'],state='Z',threads=1)
                        c.actors[actor['pid']]=actor;row.update(actor=dict(actor),registered=True)
                    original=c.native_proc
                    def fault(pid):
                        if pid==980011:raise U.UiSessionError('process_unknown')
                        return original(pid)
                    with mock.patch.object(U,'_proc',side_effect=fault),mock.patch.object(U.os,'kill') as kill:
                        with self.assertRaises(U.UiSessionError):U._guardian_stop_audio(c.rows,c.worker,c.boot,time.monotonic()+2)
                    self.assertIsNotNone(c.rows[0]['failure']);self.assertTrue(c.rows[1]['no_live_producer'])
                    self.assertEqual(2,len(c.rows[1]['observations']));kill.assert_not_called()
            finally:c.close()
            cases.append('one_unknown_actor_does_not_skip_remaining_known_terminal_original')

            c=context('mutex');c.release_read=threading.Event();c.read_waiting=threading.Event()
            errors=[]
            try:
                with c.patches():
                    def handler():
                        try:c.audio.play('HOST_AUDIO_PATH')
                        except BaseException as error:errors.append(error)
                    thread=threading.Thread(target=handler);thread.start()
                    self.assertTrue(c.read_waiting.wait(timeout=1))
                    acquired=c.channel.lock.acquire(blocking=False)
                    if acquired:c.channel.lock.release()
                    self.assertFalse(acquired)
                    c.release_read.set();thread.join(timeout=2)
                    self.assertFalse(thread.is_alive());self.assertEqual([],errors)
                    c.audio.audio_reader.join(timeout=1)
                    c.channel.prevent_new()
                    with c.channel.lock:c.channel.terminal=True
                    before=list(c.events)
                    with self.assertRaises(U.UiSessionError):c.channel.report('prepare',c.audio.tickets[0])
                    self.assertEqual(before,c.events)
            finally:c.release_read.set();c.close()
            cases.append('actual_rlock_serializes_ack_and_terminal_then_blocks_late_pipe_reader')

            c=context('inventory')
            try:
                with c.patches():
                    for number in range(1,33):
                        U._guardian_audio_frame('AUDIO_PREPARE %d 71 0 25'%number,c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                    before=len(c.events)
                    with self.assertRaises(U.UiSessionError):
                        U._guardian_audio_frame('AUDIO_PREPARE 33 71 0 25',c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                    self.assertEqual(32,len(c.rows));self.assertEqual(before,len(c.events))
            finally:c.close()
            cases.append('guardian_intent_append_only_inventory_cap_32')

            c=context('audio_cap')
            try:
                with c.patches():
                    with mock.patch.object(A.FileCenterAudio,'stop_audio'):
                        c.audio.tickets.extend([{} for unused in range(32)])
                        with self.assertRaises(ValueError):c.audio.play('HOST_AUDIO_PATH')
                    self.assertEqual([],c.events);self.assertEqual([],c.source_calls)
                    c.audio.tickets.clear()
            finally:c.close()
            cases.append('audio_cap_32_refuses_before_spawn_source_fd_or_new_intent')

            c=context('ancestry')
            try:
                with c.patches():
                    U._guardian_audio_frame('AUDIO_PREPARE 1 71 0 25',c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                    row=c.rows[0];actor=dict(c.worker,pid=980100,start='1000',parent=1,state='T',args=row['wrapper'])
                    c.actors[actor['pid']]=actor
                    with self.assertRaises(U.UiSessionError):
                        U._guardian_audio_frame('AUDIO 1 980100 1000',c.rows,c.worker,dict(boot=c.boot),c.guard_write_fd,False)
                    self.assertFalse(row['registered']);self.assertIsNone(row['actor'])
                    self.assertNotIn('AUDIO_ACK',c.events)
            finally:c.close()
            cases.append('foreign_worker_ancestry_cannot_register_or_receive_resume_ack')

        self.assertEqual(13,len(cases))
        for name in cases:print('HOST_GUARDIAN_CASE='+name)
        print('RECEIVE_FILECENTER_GUARDIAN_AUDIO_CONTRACTS=13')


if __name__=='__main__':unittest.main(verbosity=0)
