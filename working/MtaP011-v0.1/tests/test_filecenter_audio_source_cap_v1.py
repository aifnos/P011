"""New audio source-cap paths only; no historical suite is replayed.

Both real FC9 dependency families, locks, tempfile roots and serving/holder
threads run on POSIX. Their private Companion/root/guard is an explicit HOST
fixture, not native Owner admission. Audio play tests use explicit Popen,
guardian ACK and reader doubles: no process, signal, gst or media is started.
The real clock and original play/stop/source-lock methods are retained.
No ADB, P011, RF, GUI, credential, transfer or blocking-file-IO proof is made.
"""
import ast
from contextlib import contextmanager
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
NEW = ROOT/'candidate/filecenter-audio-source-cap-v1'
MISSING = object()
MOTHERS = (
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
    ('candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py', 27656,
     '57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd'),
    ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py', 35198,
     '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca'),
)
COMMON = (
    ('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py'),
    ('mta_toolbox_minhttp', 'candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py'),
    ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py'),
    ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py'),
    ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py'),
    ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py'),
    ('mta_filecenter_audio', 'candidate/filecenter-audio-source-cap-v1/shared/mta_filecenter_audio.py'),
)


@contextmanager
def family(branch):
    """Actual nine source bodies; alias restoration is not Owner authority."""
    if branch not in ('send', 'receive'): raise ValueError('HOST family selector')
    storage = ('candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py'
               if branch == 'send' else
               'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py')
    selected = COMMON + (
        ('mta_filecenter_storage', storage),
        ('mta_filecenter_companion', 'candidate/filecenter-audio-source-cap-v1/'+branch+'/mta_filecenter_companion.py'),
    )
    saved = {name:sys.modules.get(name, MISSING) for name, path in selected}
    modules = {}
    try:
        for name, path in selected:
            module = types.ModuleType(name); module.__file__ = str(ROOT/path)
            modules[name] = module; sys.modules[name] = module
            exec(compile((ROOT/path).read_bytes(), module.__file__, 'exec'), module.__dict__)
        yield modules['mta_filecenter_audio'], modules['mta_filecenter_companion']
    finally:
        for name, value in saved.items():
            if value is MISSING: sys.modules.pop(name, None)
            else: sys.modules[name] = value


class ProcessDouble:
    """Explicit HOST stopped-wrapper outcome. No OS child or signal exists."""
    def __init__(self, command, **kwargs):
        self.command = tuple(command)
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
        self.code = None; self.signals = []
    def poll(self): return self.code
    def send_signal(self, number): self.signals.append(number)
    def terminate(self): self.code = -15
    def kill(self): self.code = -9
    def wait(self, timeout=None):
        if self.code is None: raise AssertionError('HOST double still alive')
        return self.code


class AudioSourceCapTests(unittest.TestCase):
    def hold(self, lock):
        entered, release = threading.Event(), threading.Event()
        def run():
            with lock:
                entered.set()
                if not release.wait(4.0): raise AssertionError('HOST holder cleanup missing')
        holder = threading.Thread(target=run)
        holder.start(); self.assertTrue(entered.wait(1.0))
        return release, holder

    @contextmanager
    def play_fixture(self, audio, value, guardian):
        processes, reader_calls = [], []
        def spawn(command, **kwargs):
            proc = ProcessDouble(command, **kwargs); processes.append(proc)
            return proc
        def reader(instance, proc, generation, stop, stdout, stderr):
            reader_calls.append((instance, proc, generation))
            stop.wait(0.5)
        with mock.patch.object(audio.os.path, 'isfile', return_value=True), \
                mock.patch.object(audio.subprocess, 'Popen', side_effect=spawn), \
                mock.patch.object(audio.FileCenterAudio, 'read_audio', reader), \
                mock.patch.object(signal, 'SIGCONT', 18, create=True):
            value.bind_guardian(guardian)
            try:
                yield processes, reader_calls
            finally:
                # Original stop/retained actor receipts run; doubles never
                # become a real process or a target guardian acknowledgement.
                value.stop_audio(cleanup_until=float(time.monotonic()+1.0))
                self.assertTrue(value.actors_closed())

    def test_new_sources_python35_and_exact_byte_inverse(self):
        old = []
        for path, count, digest in MOTHERS:
            raw = (ROOT/path).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (count, digest))
            old.append(raw.decode('utf-8'))
        audio = (NEW/'shared/mta_filecenter_audio.py').read_text(encoding='utf-8')
        ast.parse(audio, feature_version=(3, 5))
        start = audio.index('    def bind_source_fd_deadline(self, callback):\n')
        end = audio.index('    def bind_guardian(self, notify):\n')
        added = '\n'+audio[start:end]
        self.assertEqual(audio.count(added), 1)
        inverse = audio.replace(added, '', 1)
        replacements = (
            ('        self.source_fd_deadline = self._source_fd_deadline_original = None\n', ''),
            ('        source_callback = self._source_fd_deadline_original\n', ''),
            ('        fd = self._source_fd_for_startup(path, startup_until)\n', '        fd = self.source_fd(path)\n'),
            ('                if self._source_fd_deadline_original is not source_callback:\n'
             "                    raise ValueError('original_audio_source_callback_changed')\n", ''),
            ('                if self._source_fd_for_startup(path, startup_until) != fd:\n',
             '                if self.source_fd(path) != fd:\n'),
            ("                if time.monotonic() >= startup_until: raise ValueError('audio_startup_deadline')\n"
             "                ticket['resume_called'] = True\n", "                ticket['resume_called'] = True\n"),
        )
        for before, after in replacements:
            self.assertEqual(inverse.count(before), 1)
            inverse = inverse.replace(before, after, 1)
        self.assertEqual(inverse.encode('utf-8'), old[0].encode('utf-8'))
        for index, branch in enumerate(('send', 'receive'), 1):
            text = (NEW/branch/'mta_filecenter_companion.py').read_text(encoding='utf-8')
            ast.parse(text, feature_version=(3, 5))
            changed = '            source_callback = self.audio_source_fd\n' \
                      '            self.audio.source_fd = source_callback\n' \
                      '            self.audio.bind_source_fd_deadline(source_callback)\n'
            self.assertEqual(text.count(changed), 1)
            text = text.replace(changed, '            self.audio.source_fd = self.audio_source_fd\n', 1)
            changed = '    def audio_source_fd(self, path, deadline=None):\n' \
                      '        self.check()\n' \
                      '        with _MediaLock(self, self.media_lock, deadline):\n'
            self.assertEqual(text.count(changed), 1)
            text = text.replace(changed, '    def audio_source_fd(self, path):\n'
                                '        self.check()\n'
                                '        with _MediaLock(self, self.media_lock):\n', 1)
            self.assertEqual(text.encode('utf-8'), old[index].encode('utf-8'))

    def test_legacy_one_argument_and_no_typeerror_signature_guess(self):
        with family('send') as (audio, companion), tempfile.TemporaryDirectory(prefix='p011-source-legacy-') as folder:
            calls = []
            def legacy(path): calls.append((path,)); return 17
            value = audio.FileCenterAudio(folder, lambda event:None, legacy)
            self.assertEqual(value._source_fd_for_startup('HOST only path', float(time.monotonic()+1)), 17)
            self.assertEqual(calls, [('HOST only path',)])
            with self.play_fixture(audio, value, lambda phase, ticket:True):
                value.play('HOST legacy play path')
                self.assertEqual(calls, [('HOST only path',),
                                        ('HOST legacy play path',), ('HOST legacy play path',)])
            typed_calls = []
            marker = TypeError('HOST callback internal error')
            def typed(path, deadline=None): typed_calls.append((path, deadline)); raise marker
            value = audio.FileCenterAudio(folder, lambda event:None, typed)
            value.bind_source_fd_deadline(typed)
            cap = float(time.monotonic()+1)
            with self.assertRaises(TypeError) as caught:
                value._source_fd_for_startup('HOST only path', cap)
            self.assertIs(caught.exception, marker)
            self.assertEqual(len(typed_calls), 1)
            self.assertIs(typed_calls[0][1], cap)

    def test_sealed_callback_identity_before_and_after_lookup(self):
        with family('send') as (audio, companion), tempfile.TemporaryDirectory(prefix='p011-source-seal-') as folder:
            calls = []
            def original(path, deadline=None): calls.append(path); return 17
            def changed(path, deadline=None): raise AssertionError('changed callback ran')
            value = audio.FileCenterAudio(folder, lambda event:None, original)
            value.bind_source_fd_deadline(original)
            with self.assertRaisesRegex(ValueError, 'original_audio_source_callback_required'):
                value.bind_source_fd_deadline(original)
            for field in ('source_fd', 'source_fd_deadline'):
                setattr(value, field, changed)
                with self.assertRaisesRegex(ValueError, 'original_audio_source_callback_changed'):
                    value._source_fd_for_startup('HOST only path', float(time.monotonic()+1))
                setattr(value, field, original)
            self.assertEqual(calls, [])
            def mutating(path, deadline=None):
                value.source_fd_deadline = changed
                return 17
            value = audio.FileCenterAudio(folder, lambda event:None, mutating)
            value.bind_source_fd_deadline(mutating)
            with self.assertRaisesRegex(ValueError, 'original_audio_source_callback_changed'):
                value._source_fd_for_startup('HOST only path', float(time.monotonic()+1))

    def test_play_both_source_lookups_share_absolute_cap_and_fd_check(self):
        for changed_fd in (False, True):
            with self.subTest(changed_fd=changed_fd), family('send') as (audio, companion), \
                    tempfile.TemporaryDirectory(prefix='p011-source-two-lookups-') as folder:
                calls, guardian_phases = [], []
                cap = float(time.monotonic()+2.0)
                def source(path, deadline=None):
                    calls.append((path, deadline))
                    return 18 if changed_fd and len(calls) == 2 else 17
                def guardian(phase, ticket): guardian_phases.append(phase); return True
                value = audio.FileCenterAudio(folder, lambda event:None, source, parent_until=cap)
                value.bind_source_fd_deadline(source)
                with self.play_fixture(audio, value, guardian) as (processes, readers):
                    if changed_fd:
                        with self.assertRaisesRegex(ValueError, 'original_audio_fd_changed'):
                            value.play('HOST only path')
                    else: value.play('HOST only path')
                    self.assertEqual(len(calls), 2)
                    self.assertIs(calls[0][1], cap); self.assertIs(calls[1][1], cap)
                    self.assertIs(value.parent_until, cap)
                    self.assertEqual(guardian_phases, ['prepare', 'register'])
                    self.assertEqual(len(processes), 1)
                    ticket = value.tickets[0]
                    self.assertEqual(ticket['resume_called'], not changed_fd)
                    self.assertEqual(ticket['start_called'], not changed_fd)
                    if changed_fd:
                        self.assertEqual(processes[0].signals, [])
                        self.assertEqual(readers, [])

    def test_expired_callback_return_before_spawn_and_after_guardian_never_resumes(self):
        for delayed_phase in ('first_source', 'guardian', 'second_source'):
            with self.subTest(phase=delayed_phase), family('send') as (audio, companion), \
                    tempfile.TemporaryDirectory(prefix='p011-source-expiry-') as folder:
                calls = []
                cap = float(time.monotonic()+0.10)
                def source(path, deadline=None):
                    calls.append(deadline)
                    if ((delayed_phase == 'first_source' and len(calls) == 1) or
                            (delayed_phase == 'second_source' and len(calls) == 2)):
                        threading.Event().wait(0.15)
                    return 17
                def guardian(phase, ticket):
                    if delayed_phase == 'guardian' and phase == 'register':
                        threading.Event().wait(0.15)
                    return True
                value = audio.FileCenterAudio(folder, lambda event:None, source, parent_until=cap)
                value.bind_source_fd_deadline(source)
                with self.play_fixture(audio, value, guardian) as (processes, readers):
                    with self.assertRaisesRegex(ValueError, 'audio_startup_deadline'):
                        value.play('HOST only path')
                    self.assertTrue(all(deadline is cap for deadline in calls))
                    self.assertEqual(readers, [])
                    if delayed_phase == 'first_source':
                        self.assertEqual(processes, []); self.assertEqual(value.tickets, [])
                    else:
                        self.assertEqual(len(processes), 1)
                        self.assertEqual(processes[0].signals, [])
                        self.assertFalse(value.tickets[0]['resume_called'])
                        self.assertFalse(value.tickets[0]['start_called'])

    def test_guardian_cannot_replace_both_visible_and_retained_callback(self):
        with family('send') as (audio, companion), \
                tempfile.TemporaryDirectory(prefix='p011-source-guardian-swap-') as folder:
            calls = []
            def source(path, deadline=None): calls.append(path); return 17
            def replaced(path, deadline=None): raise AssertionError('replacement callback ran')
            value = audio.FileCenterAudio(folder, lambda event:None, source)
            value.bind_source_fd_deadline(source)
            def guardian(phase, ticket):
                if phase == 'register':
                    value.source_fd = replaced
                    value.source_fd_deadline = value._source_fd_deadline_original = replaced
                return True
            with self.play_fixture(audio, value, guardian) as (processes, readers):
                with self.assertRaisesRegex(ValueError, 'original_audio_source_callback_changed'):
                    value.play('HOST only path')
                self.assertEqual(calls, ['HOST only path'])
                self.assertEqual(processes[0].signals, []); self.assertEqual(readers, [])
                self.assertFalse(value.tickets[0]['resume_called'])
                self.assertFalse(value.tickets[0]['start_called'])

    @unittest.skipUnless(os.name == 'posix', 'actual confined tempfile storage requires POSIX directory flags')
    def test_actual_companion_callback_lock_obeys_short_cap_in_both_families(self):
        for branch in ('send', 'receive'):
            with self.subTest(branch=branch), family(branch) as (audio, companion), \
                    tempfile.TemporaryDirectory(prefix='p011-source-lock-'+branch+'-') as folder:
                parent = float(time.monotonic()+20.0)
                value = companion._Companion(folder, parent, lambda:True)
                release, holder = self.hold(value.media_lock)
                try:
                    callback = value.audio._source_fd_deadline_original
                    self.assertIs(value.audio.source_fd, callback)
                    self.assertIs(value.audio.source_fd_deadline, callback)
                    self.assertIs(callback.__self__, value)
                    cap = float(time.monotonic()+0.12)
                    began = time.monotonic()
                    with mock.patch.object(audio.subprocess, 'Popen', side_effect=AssertionError('HOST unexpected child')) as popen:
                        with self.assertRaisesRegex(ValueError, 'filecenter_media_lock_deadline'):
                            value.audio._source_fd_for_startup('HOST nonexistent source', cap)
                        self.assertEqual(popen.call_count, 0)
                    elapsed = time.monotonic()-began
                    self.assertGreaterEqual(elapsed, 0.06); self.assertLess(elapsed, 0.65)
                    self.assertIs(value.until, parent)
                    self.assertIs(value.audio._parent_until_original, parent)
                    self.assertTrue(holder.is_alive()); self.assertEqual(value.media, [])
                    print('HOST_SOURCE_CALLBACK_%s_LOCK_SECONDS=%.6f' % (branch.upper(), elapsed))
                finally:
                    release.set(); holder.join(1.0)
                    self.assertFalse(holder.is_alive())
                    self.assertTrue(value.close(cleanup_until=float(time.monotonic()+1.0)))
                    self.assertTrue(value.closed())
                self.assertTrue(value.media_lock.acquire(False)); value.media_lock.release()

    @unittest.skipUnless(os.name == 'posix', 'actual confined tempfile storage requires POSIX directory flags')
    def test_original_close_cancels_waiting_callback_without_releasing_holder(self):
        for branch in ('send', 'receive'):
            with self.subTest(branch=branch), family(branch) as (audio, companion), \
                    tempfile.TemporaryDirectory(prefix='p011-source-cancel-'+branch+'-') as folder:
                worker = threading.current_thread(); waiting = threading.Event()
                def guard():
                    if threading.current_thread() is not worker: waiting.set()
                    return True  # Explicit private HOST guard, not native Owner.
                parent = float(time.monotonic()+20.0)
                value = companion._Companion(folder, parent, guard)
                release, holder = self.hold(value.media_lock)
                result = []
                def lookup():
                    try: result.append(value.audio._source_fd_for_startup(
                        'HOST nonexistent source', float(time.monotonic()+2.0)))
                    except BaseException as error: result.append(error)
                waiter = threading.Thread(target=lookup); waiter.start()
                try:
                    self.assertTrue(waiting.wait(1.0))
                    began = time.monotonic()
                    self.assertTrue(value.close(cleanup_until=float(time.monotonic()+1.0)))
                    waiter.join(0.5)
                    self.assertFalse(waiter.is_alive())
                    self.assertEqual(len(result), 1)
                    self.assertIsInstance(result[0], ValueError)
                    self.assertEqual(str(result[0]), 'filecenter_session_ended')
                    self.assertLess(time.monotonic()-began, 1.5)
                    self.assertTrue(holder.is_alive())
                    self.assertTrue(value.closed())
                    self.assertEqual(value.audio.tickets, []); self.assertEqual(value.media, [])
                    self.assertIs(value.until, parent)
                finally:
                    release.set(); holder.join(1.0); waiter.join(1.0)
                    if not value.close_called: value.close(cleanup_until=float(time.monotonic()+1.0))
                    self.assertFalse(holder.is_alive()); self.assertFalse(waiter.is_alive())
                self.assertTrue(value.media_lock.acquire(False)); value.media_lock.release()


if __name__ == '__main__': unittest.main(verbosity=2)
