# -*- coding: utf-8 -*-
"""HOST-only mocks: never open /proc or change this test process's score."""
import ctypes
import os
import pathlib
import sys
import unittest
from unittest import mock

RUNTIME = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
import guardian


class ChildExit(BaseException):
    pass


class ChildOomTests(unittest.TestCase):
    def test_score_targets_only_preexec_self_and_writes_fixed_value(self):
        with mock.patch.object(os, 'open', return_value=70) as opened, \
             mock.patch.object(os, 'write', return_value=4) as written, \
             mock.patch.object(os, 'close') as closed, \
             mock.patch.object(os, '_exit') as exited:
            guardian.set_child_oom_priority()
        opened.assert_called_once_with('/proc/self/oom_score_adj', os.O_WRONLY)
        written.assert_called_once_with(70, b'500\n')
        closed.assert_called_once_with(70)
        exited.assert_not_called()

    def test_open_write_short_write_or_close_failure_aborts_125(self):
        failures = ({'open': OSError(13, 'denied')}, {'write': OSError(5, 'io')},
                    {'short': True}, {'close': OSError(5, 'io')})
        for failure in failures:
            with mock.patch.object(os, 'open', return_value=70, side_effect=failure.get('open')), \
                 mock.patch.object(os, 'write', return_value=0 if failure.get('short') else 4,
                                   side_effect=failure.get('write')), \
                 mock.patch.object(os, 'close', side_effect=failure.get('close')), \
                 mock.patch.object(os, '_exit', side_effect=ChildExit) as exited:
                with self.assertRaises(ChildExit):
                    guardian.set_child_oom_priority()
            exited.assert_called_once_with(125)

    def test_oom_is_applied_before_birth_and_dropping_child_credentials(self):
        events = []
        library = mock.Mock()
        library.setrlimit.return_value = 0
        def record(name):
            return lambda *args: events.append(name)
        with mock.patch.object(ctypes, 'CDLL', return_value=library), \
             mock.patch.object(os, 'umask'), \
             mock.patch.object(guardian, 'set_child_oom_priority', side_effect=record('oom')), \
             mock.patch.object(guardian, 'identity', return_value={'pid': 10}), \
             mock.patch.object(os, 'getpid', return_value=10), \
             mock.patch.object(os, 'write', side_effect=record('birth')), \
             mock.patch.object(os, 'close'), \
             mock.patch.object(os, 'geteuid', side_effect=[0, 65534, 65534], create=True), \
             mock.patch.object(os, 'getegid', return_value=44, create=True), \
             mock.patch.object(os, 'setgroups', side_effect=record('setgroups'), create=True), \
             mock.patch.object(os, 'setgid', side_effect=record('setgid'), create=True), \
             mock.patch.object(os, 'setuid', side_effect=record('setuid'), create=True), \
             mock.patch.object(os, '_exit') as exited:
            guardian.child_preexec(65534, 44, 71)()
        self.assertEqual(events, ['oom', 'birth', 'setgroups', 'setgid', 'setuid'])
        exited.assert_not_called()


if __name__ == '__main__':
    unittest.main()
