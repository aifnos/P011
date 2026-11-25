"""Unexecuted v78 SOURCE: five original Session start-cap cases, one method.

The actual new module definitions, constructor and start method are used in an
explicit HOST definition domain. The clock is a fixed HOST model and every
Thread.start is intercepted, never forwarded. Real Thread objects are retained
but no worker, finalizer, lifecycle cleanup or restore runs. The old TestCase is
not imported or replayed. This tests time-only bounds, not admission, radio,
device/phone behavior, service operation or physical restoration.
"""
import hashlib
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = 'candidate/go-send-state-v78/runtime/mta_transfer_session.py'
SOURCE_PIN = (20633, 'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859')
METHOD = 'test_original_absolute_cap'
MARKER = ('HOST78_SESSION_CAP new_methods=1 old_methods=0 cases=5 '
          'threads_model=true device=false phone=false\n')


def _definitions():
    path = BASE / SOURCE
    raw = path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != SOURCE_PIN:
        raise ValueError('session_source_identity_changed')
    value = types.ModuleType('session_absolute_v78_private_definition')
    value.__file__ = str(path)
    # Definition execution only in ROOT's future unique child. This SOURCE
    # author never imports/executes the production module or this test.
    exec(compile(raw.decode('utf-8'), str(path), 'exec'), value.__dict__)
    return value


class _IntSubclass(int):
    pass


class _FloatSubclass(float):
    pass


class AbsoluteSession78Test(unittest.TestCase):
    def test_original_absolute_cap(self):
        module = _definitions()
        starts, sessions, completed = [], [], []
        constructor_refusals = start_refusals = 0
        task = mock.Mock(side_effect=AssertionError('HOST78 task must remain uncalled'))
        restore = mock.Mock(side_effect=AssertionError('HOST78 restore must remain uncalled'))
        extra = mock.Mock(side_effect=AssertionError('HOST78 extra cleanup must remain uncalled'))
        lease = object()  # Inert required callback owner, never an authority.

        def construct(**options):
            value = module.TransferSession(task, restore, lease,
                extra_actor_close=extra, task_timeout=300, finalize_timeout=30, **options)
            sessions.append(value)
            self.assertIs(type(value), module.TransferSession)
            self.assertIs(value._lease_owner, lease)
            self.assertIs(value._task, task)
            self.assertIs(value._restore, restore)
            self.assertIs(value._extra, extra)
            self.assertEqual(300.0, value.task_timeout)
            self.assertEqual(30.0, value.finalize_timeout)
            self.assertEqual(1, len(value._attempts))
            self.assertIs(value._worker._target.__self__, value)
            self.assertIs(value._worker._target.__func__, module.TransferSession._worker_main)
            self.assertIs(value._attempts[0]['thread']._target.__self__, value)
            self.assertIs(value._attempts[0]['thread']._target.__func__, module.TransferSession._finalizer_main)
            return value

        def unclaimed(value):
            self.assertIs(value._started, False)
            self.assertIs(value._worker_start_claimed, False)
            self.assertIs(value._worker_start_resolved, False)
            self.assertIs(value._worker_start_failed, False)
            self.assertIs(value._worker_start_unknown, False)
            self.assertIsNone(value._task_deadline)
            self.assertEqual('prepared', value._phase)
            self.assertIs(value._attempts[0]['claimed'], False)
            self.assertIs(value._attempts[0]['resolved'], False)
            self.assertIs(value._attempts[0]['unknown_start'], False)

        def intercepted(thread):
            starts.append(thread)
            return None  # Deliberately NOT original Thread.start or Thread.run.

        with mock.patch.object(module.threading.Thread, 'start', autospec=True,
                               side_effect=intercepted) as mocked_start, \
                mock.patch.object(module.time, 'monotonic', return_value=100.0) as clock:
            with self.subTest(case='finite_typed_constructor'):
                invalids = (True, False, 0, -1, float('inf'), float('-inf'),
                            float('nan'), '150', object(), 2 ** 53, 10 ** 1000,
                            _IntSubclass(150), _FloatSubclass(150.0))
                for invalid in invalids:
                    before = mocked_start.call_count
                    with self.assertRaises(module.SessionError) as caught:
                        construct(absolute_until=invalid)
                    self.assertEqual(('invalid_absolute_until',), caught.exception.args)
                    self.assertEqual(before, mocked_start.call_count)
                    constructor_refusals += 1
                self.assertEqual(13, constructor_refusals)
                self.assertEqual([], sessions)
                self.assertEqual(0, clock.call_count)
                completed.append('finite_typed_constructor')

            with self.subTest(case='expired_original_before_actor_start'):
                value = construct(absolute_until=100.0)
                original = value._absolute_until_original
                self.assertIs(value._absolute_until, original)
                before = mocked_start.call_count
                with self.assertRaises(module.SessionError) as caught:
                    value.start()
                self.assertEqual(('absolute_until_expired',), caught.exception.args)
                self.assertEqual(before, mocked_start.call_count)
                self.assertIs(value._absolute_until_original, original)
                self.assertIs(value._absolute_until, original)
                unclaimed(value)
                start_refusals += 1
                completed.append('expired_original_before_actor_start')

            with self.subTest(case='original_field_replacement_before_actor_start'):
                value = construct(absolute_until=150.0)
                original = value._absolute_until_original
                replacement = float('150.0')
                self.assertEqual(original, replacement)
                self.assertIsNot(original, replacement)
                value._absolute_until = replacement  # Explicit deny-only HOST mutation.
                before, clock_before = mocked_start.call_count, clock.call_count
                with self.assertRaises(module.SessionError) as caught:
                    value.start()
                self.assertEqual(('absolute_until_changed',), caught.exception.args)
                self.assertEqual(before, mocked_start.call_count)
                self.assertEqual(clock_before, clock.call_count)
                self.assertIs(value._absolute_until_original, original)
                self.assertIs(value._absolute_until, replacement)
                unclaimed(value)
                start_refusals += 1
                completed.append('original_field_replacement_before_actor_start')

            with self.subTest(case='finite_service_clamp_150'):
                value = construct(absolute_until=150)
                original = value._absolute_until_original
                before = mocked_start.call_count
                self.assertIs(value.start(), value)
                self.assertEqual(150.0, value._task_deadline)
                self.assertIs(value._task_deadline, original)
                self.assertIs(value._absolute_until, original)
                self.assertIs(value._absolute_until_original, original)
                self.assertEqual(before + 2, mocked_start.call_count)
                self.assertIs(starts[-2], value._worker)
                self.assertIs(starts[-1], value._attempts[0]['thread'])
                self.assertIs(value._started, True)
                self.assertIs(value._worker_start_claimed, True)
                self.assertIs(value._worker_start_resolved, True)
                self.assertIs(value._worker_start_unknown, False)
                self.assertIs(value._attempts[0]['claimed'], True)
                self.assertIs(value._attempts[0]['resolved'], True)
                self.assertIs(value._attempts[0]['unknown_start'], False)
                completed.append('finite_service_clamp_150')

            with self.subTest(case='none_legacy_relative_400'):
                value = construct()  # Original omitted-argument path, not new authority.
                self.assertIsNone(value._absolute_until)
                self.assertIsNone(value._absolute_until_original)
                before = mocked_start.call_count
                self.assertIs(value.start(), value)
                self.assertEqual(400.0, value._task_deadline)
                self.assertIsNone(value._absolute_until)
                self.assertIsNone(value._absolute_until_original)
                self.assertEqual(before + 2, mocked_start.call_count)
                self.assertIs(starts[-2], value._worker)
                self.assertIs(starts[-1], value._attempts[0]['thread'])
                self.assertIs(value._worker_start_unknown, False)
                self.assertIs(value._attempts[0]['unknown_start'], False)
                completed.append('none_legacy_relative_400')

            self.assertEqual(3, clock.call_count)
            self.assertEqual(4, mocked_start.call_count)
            self.assertEqual(4, len(starts))

        self.assertEqual(['finite_typed_constructor', 'expired_original_before_actor_start',
            'original_field_replacement_before_actor_start', 'finite_service_clamp_150',
            'none_legacy_relative_400'], completed)
        self.assertEqual(13, constructor_refusals)
        self.assertEqual(2, start_refusals)
        self.assertEqual(4, len(sessions))
        for callback in (task, restore, extra):
            self.assertEqual(0, callback.call_count)
        for value in sessions:
            for actor in (value._worker, value._attempts[0]['thread']):
                self.assertIsNone(actor.ident)
                self.assertIs(actor.is_alive(), False)
            # Unexecuted callback/lifecycle facts stay false even when the start
            # call was intercepted. Never treat the modeled start as closure.
            self.assertIs(value._restore_done, False)
            self.assertIs(value._extra_done, False)
            self.assertIs(value._all_stages_done, False)
            self.assertIsNone(value._outcome)
            self.assertEqual([], value._transports)
            self.assertEqual([], value._handoffs)
            self.assertEqual([], value._unknown)


def _main():
    if sys.argv[1:] not in ([], ['-q']):
        return 2
    suite = unittest.TestSuite([AbsoluteSession78Test(METHOD)])
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=0).run(suite)
    if result.wasSuccessful():
        sys.stdout.write(MARKER)
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(_main())
