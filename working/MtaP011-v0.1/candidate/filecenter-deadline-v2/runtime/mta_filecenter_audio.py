"""Retained-actor launch adapter for the original gst-play position engine.

Only the fixed gst-play argv may play audio. The formal caller first launches
the sealed self-stopped Python wrapper and waits for its original guardian ACK;
the independent HOST seam remains direct, with no guardian assurance.
read_audio/snapshot/stop are reused; every original actor stays in tickets.
"""
import os
import math
import signal
import subprocess
import sys
import threading
import time
from mta_toolbox_audio import AudioEngine


# Also sealed in the fixed UI guardian source. The child cannot execute the
# audio program until its exact stopped PID/start/argv has been acknowledged.
GUARDIAN_WRAPPER = ('import os,signal,sys;'
    'os.kill(os.getpid(),signal.SIGSTOP);'
    'os.execve(sys.argv[1],sys.argv[1:],os.environ)')


class FileCenterAudio(AudioEngine):
    def __init__(self, logs, event, source_fd, parent_until=None):
        if parent_until is not None and (type(parent_until) is not float or not math.isfinite(parent_until)):
            raise ValueError('original_finite_audio_cap_required')
        AudioEngine.__init__(self, logs, event)
        self.parent_until = self._parent_until_original = parent_until
        self.cleanup_pending = False
        self.cleanup_until = None
        self.source_fd = source_fd
        self.tickets = []
        self.guardian_notify = self._guardian_original = None

    def bind_guardian(self, notify):
        # The formal fixed caller authenticates the original instance, source
        # class and closure. This is not an HTTP/UI callback registration API.
        if not callable(notify) or self._guardian_original is not None or self.tickets:
            raise ValueError('original_audio_guardian_required')
        self.guardian_notify = self._guardian_original = notify

    def _notify_guardian(self, phase, ticket):
        if self.guardian_notify is not self._guardian_original:
            raise ValueError('original_audio_guardian_changed')
        if self._guardian_original is None:
            return False  # Existing independent HOST seam, not guardian proof.
        if self._guardian_original(phase, ticket) is not True:
            raise ValueError('audio_guardian_not_acknowledged')
        return True

    def play(self, path, volume=25):
        if type(volume) is not int or not 0 <= volume <= 100:
            raise ValueError('音量无效')
        if self.parent_until is not self._parent_until_original:
            raise ValueError('original_audio_cap_changed')
        startup_until = time.monotonic() + 4.0
        if self._parent_until_original is not None:
            startup_until = min(startup_until, self._parent_until_original)
        self.stop_audio(cleanup_until=startup_until)
        if time.monotonic() >= startup_until: raise ValueError('audio_startup_deadline')
        if len(self.tickets) >= 32:
            raise ValueError('本次会话播放次数已达上限，请退出后重新打开')
        fd = self.source_fd(path)
        gst = next((p for p in ('/usr/bin/gst-play-1.0', '/bin/gst-play-1.0')
                    if os.path.isfile(p)), None)
        if gst is None:
            raise RuntimeError('此环境无 gst-play 音频后端')
        self.audio_generation += 1
        generation = self.audio_generation
        self.audio_state = self.new_audio_state(generation, 'starting')
        ticket = dict(process=None, reader=None, stop=None, streams=[],
                      spawn_called=False, spawn_returned=False,
                      reader_initialized=False, start_called=False,
                      start_returned=False, failure=None,
                      source_fd=fd, command=None, spawn_command=None,
                      guardian_required=self._guardian_original is not None,
                      guardian_prepare_called=False, guardian_prepared=False,
                      guardian_register_called=False, guardian_registered=False,
                      guardian_cancel_called=False, guardian_cancelled=False,
                      resume_called=False, resume_returned=False, cleanup_failure=None)
        self.tickets.append(ticket)
        try:
            for suffix in ('stdout', 'stderr'):
                ticket['streams'].append(open(self.logs+'/audio-%d.%s.raw' %
                    (generation, suffix), 'xb', buffering=0))
            command = [gst, '--no-interactive', '--audiosink=pulsesink',
                '--volume=%.2f' % (volume/100.0),
                'file:///proc/%d/fd/%d' % (os.getpid(), fd)]
            ticket['command'] = tuple(command)
            protected = ticket['guardian_required']
            spawn_command = ([sys.executable, '-c', GUARDIAN_WRAPPER] + command
                             if protected else command)
            ticket['spawn_command'] = tuple(spawn_command)
            env = dict(os.environ); env['LC_ALL'] = 'C'
            if protected:
                ticket['guardian_prepare_called'] = True
                self._notify_guardian('prepare', ticket)
                ticket['guardian_prepared'] = True
            if time.monotonic() >= startup_until: raise ValueError('audio_startup_deadline')
            ticket['spawn_called'] = True
            proc = subprocess.Popen(spawn_command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, env=env)
            ticket['process'] = self.audio = proc
            ticket['spawn_returned'] = True
            ticket['streams'].extend((proc.stdout, proc.stderr))
            if time.monotonic() >= startup_until: raise ValueError('audio_startup_deadline')
            if protected:
                ticket['guardian_register_called'] = True
                # The fixed caller observes and authenticates the self-stopped
                # wrapper through actual /proc before requesting the ACK.
                self._notify_guardian('register', ticket)
                ticket['guardian_registered'] = True
                if proc.poll() is not None:
                    raise ValueError('audio_wrapper_exited')
                if self.source_fd(path) != fd:
                    raise ValueError('original_audio_fd_changed')
                ticket['resume_called'] = True
                proc.send_signal(signal.SIGCONT)
                ticket['resume_returned'] = True
            stop = ticket['stop'] = self.audio_reader_stop = threading.Event()
            reader = threading.Thread.__new__(threading.Thread)
            ticket['reader'] = self.audio_reader = reader
            threading.Thread.__init__(reader, target=self.read_audio,
                args=(proc, generation, stop, ticket['streams'][0], ticket['streams'][1]))
            ticket['reader_initialized'] = True
            reader.daemon = True
            self.audio_state['process_alive'] = True
            if time.monotonic() >= startup_until: raise ValueError('audio_startup_deadline')
            ticket['start_called'] = True
            reader.start(); ticket['start_returned'] = True
            return self.audio_snapshot()
        except BaseException as error:
            ticket['failure'] = error
            self.audio_state.update(status='error', error='音频后端启动失败')
            if (ticket['guardian_prepare_called'] and not ticket['spawn_called'] and
                    not ticket['guardian_cancel_called']):
                ticket['guardian_cancel_called'] = True
                try:
                    self._notify_guardian('cancel', ticket)
                    ticket['guardian_cancelled'] = True
                except BaseException:
                    pass  # Preserve original failure; no invented ACK/absence.
            # Partial/unknown Thread/Popen returns remain retained, not closed.
            if ticket['spawn_returned']:
                try: self.stop_audio(cleanup_until=startup_until)
                except BaseException as cleanup_error:
                    ticket['cleanup_failure'] = cleanup_error
            elif not ticket['spawn_called']:
                for stream in ticket['streams']: stream.close()
            raise

    def audio_snapshot(self):
        if self.parent_until is not self._parent_until_original:
            raise ValueError('original_audio_cap_changed')
        deadline = time.monotonic() + 0.5
        if self._parent_until_original is not None:
            deadline = min(deadline, self._parent_until_original)
        if self.cleanup_pending and self.cleanup_until is not None:
            deadline = min(deadline, self.cleanup_until)
        remaining = lambda:max(0.0, deadline-time.monotonic())
        if not self.lock.acquire(timeout=remaining()): raise RuntimeError('audio_state_lock_pending')
        try:
            proc, reader = self.audio, self.audio_reader
            draining = proc is not None and proc.poll() is not None and self.audio_state['status'] in ('starting', 'playing')
        finally: self.lock.release()
        if draining and reader is not None and reader is not threading.current_thread():
            reader.join(timeout=remaining())
        if not self.lock.acquire(timeout=remaining()): raise RuntimeError('audio_state_lock_pending')
        try:
            state = dict(self.audio_state)
            state['process_alive'] = self.audio is not None and self.audio.poll() is None
            if not state['process_alive'] and state['status'] in ('starting', 'playing'):
                state.update(status='error', error='音频进程已退出，结束信息未完成读取',
                    exit_code=self.audio.poll() if self.audio is not None else None)
            state['playing'] = state['status']=='playing' and state['process_alive']
            return state
        finally: self.lock.release()

    def actors_closed(self):
        # Passive closure must never wait behind a reader holding the lock.
        if not self.lock.acquire(False): return False
        try:
            if self.cleanup_pending: return False
            rows = tuple(self.tickets)
        finally: self.lock.release()
        for row in rows:
            if row['spawn_called'] and not row['spawn_returned']:
                return False
            proc = row['process']; reader = row['reader']
            if proc is not None and proc.poll() is None: return False
            if reader is not None:
                if not row['reader_initialized']: return False
                if row['start_called'] and not row['start_returned']: return False
                if reader.is_alive(): return False
            if any(stream.closed is not True for stream in row['streams']): return False
        return True

    def stop_audio(self, cleanup_until=None):
        if cleanup_until is not None and (type(cleanup_until) is not float or
                not math.isfinite(cleanup_until)):
            raise ValueError('original_finite_cleanup_cap_required')
        # Standalone audio stops retain the old total maximum (2+1+1s), but
        # nested FileCenter stops never renew a parent's absolute budget.
        deadline = time.monotonic() + 4.0
        if cleanup_until is not None: deadline = min(deadline, cleanup_until)
        if self.cleanup_pending and self.cleanup_until is not None:
            deadline = min(deadline, self.cleanup_until)
        self.cleanup_until = deadline
        remaining = lambda seconds:min(seconds, max(0.0, deadline-time.monotonic()))
        self.cleanup_pending = True
        if not self.lock.acquire(timeout=remaining(4.0)):
            raise RuntimeError('audio_state_lock_pending')
        try: proc, reader, stop_reader = self.audio, self.audio_reader, self.audio_reader_stop
        finally: self.lock.release()
        if stop_reader is not None: stop_reader.set()
        failure = None
        if proc is not None and proc.poll() is None:
            try:
                try: proc.terminate()
                except ProcessLookupError: pass
                try: proc.wait(timeout=remaining(2.0))
                except subprocess.TimeoutExpired:
                    try: proc.kill()
                    except ProcessLookupError: pass
                    proc.wait(timeout=remaining(1.0))
            except BaseException as error: failure = error
        row = next((item for item in self.tickets if item['reader'] is reader and reader is not None), None)
        # Never join an unstarted reader, or reinterpret an uncertain start.
        known_unstarted = row is not None and row['reader_initialized'] and not row['start_called']
        uncertain_start = row is not None and row['start_called'] and not row['start_returned']
        reader_unknown = reader is not None and (row is None or not row['reader_initialized'])
        if reader is not None and not known_unstarted and not uncertain_start and not reader_unknown:
            try:
                if reader is threading.current_thread(): raise RuntimeError('audio_reader_self_pending')
                reader.join(timeout=remaining(1.0))
                if reader.is_alive(): raise RuntimeError('音频读取线程尚未停止')
            except BaseException as error:
                if failure is None: failure = error
        if uncertain_start and failure is None: failure = RuntimeError('audio_reader_start_pending')
        if reader_unknown and failure is None: failure = RuntimeError('audio_reader_original_pending')
        process_ended = proc is None or proc.poll() is not None
        reader_ended = reader is None or known_unstarted or (
            not reader_unknown and not uncertain_start and not reader.is_alive())
        if process_ended and reader_ended:
            # No reader can still be using these exact retained streams.
            for item in self.tickets:
                if item['process'] is proc and not (item['spawn_called'] and not item['spawn_returned']):
                    for stream in item['streams']:
                        try: stream.close()
                        except BaseException as error:
                            if failure is None: failure = error
            if not self.lock.acquire(timeout=remaining(4.0)):
                if failure is None: failure = RuntimeError('audio_state_lock_pending')
            else:
                try:
                    if self.audio is proc and self.audio_reader is reader:
                        self.audio = self.audio_reader = self.audio_reader_stop = None
                        self.audio_state = self.new_audio_state(self.audio_generation, 'stopped')
                finally: self.lock.release()
        elif failure is None: failure = RuntimeError('audio_cleanup_pending')
        # Pending actors stay in both the current fields and original tickets;
        # a request, timeout or kill is never an absence/guardian receipt.
        if failure is not None: raise failure
        self.cleanup_pending = False
        if not self.actors_closed():
            self.cleanup_pending = True
            raise RuntimeError('audio_retained_actors_pending')
        self.cleanup_until = None
