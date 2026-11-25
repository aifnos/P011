"""One new HOST method for actual startup constructors and close control.

The frozen importer fixture supplies only its fixed-input reader; no earlier
TestCase is selected, instantiated, discovered or executed. Its pinned manifest
and 34 unchanged sources plus the new executor form the actual private35 realm.
The collector SOURCE is loaded in full, not extracted/reimplemented methods.

Scope admission/closure hooks are explicit HOST models, not real Owner proof.
The clock, PID and current thread are observed on the HOST only. Deterministic
token bytes in the pure-constructor case model memory input, not real entropy.
No actual open/socket/process/thread or successful Baseline/Status read runs.
The third domain replaces only captured definition close functions and supplies
synthetic close inventories; it tests independent control flow, not FD closure,
device restoration, radio admission or successful receiving.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = 'tests/test_receive_startup_importer.py'
FIXTURE_BYTES = 19271
FIXTURE_SHA = 'dd7eba5713d839359b5bbd3b165ebbbcbf8323e9ccbcfe9a657f43c442b6dfae'
COLLECTOR_PATH = 'candidate/receive-startup-readonly-v1/runtime/mta_client_startup_readonly.py'
COLLECTOR_BYTES = 20426
COLLECTOR_SHA = '2e49f367ae1eb27e82c03ef675861639415ecbad9471a8c3a62b4999fd48ee73'
FIXTURE_NAME = '_host_receive_startup_collector_v1_input_fixture'
RUNNING_NAME = '_host_receive_startup_collector_v1_executor'
COLLECTOR_NAME = '_host_receive_startup_collector_v1_definition'
MARKER = ('HOST_RECEIVE_STARTUP_COLLECTOR new_methods=1 cases=3 '
          'actual_pure_constructors=true close_control_model=true old_methods=0 '
          'device=false phone=false rf=false\n')


def _fixed(path, size, pin):
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('fixed HOST collector input changed')
    return raw


def frozen_inputs():
    """All HOST source reads precede actual-IO tripwires; no old method runs."""
    fixture_raw = _fixed(FIXTURE_PATH, FIXTURE_BYTES, FIXTURE_SHA)
    collector_raw = _fixed(COLLECTOR_PATH, COLLECTOR_BYTES, COLLECTOR_SHA)
    fixture = types.ModuleType(FIXTURE_NAME)
    fixture.__file__ = str(ROOT / FIXTURE_PATH)
    exec(compile(fixture_raw, fixture.__file__, 'exec'), fixture.__dict__)
    sources, paths, pins = fixture.frozen_inputs()
    return fixture, collector_raw, sources, paths, pins


class _HostScopeModel(object):
    """Only constructor/clock wiring; never an actual Owner or admission."""
    def __init__(self, modules, until, manifest_sha, profile):
        self.private_modules, self.profile = modules, profile
        self.clock, self.worker, self.pid = time.monotonic, threading.current_thread(), os.getpid()
        self.original_until = until
        self.source_manifest_sha = manifest_sha
        self.collector_ticket = None
        self.active_checks = self.close_checks = 0

    def check_active(self):
        # Deliberately no model expiry shortcut: actual collection._now owns
        # the tested startup_deadline rejection after complete construction.
        self.active_checks += 1
        return self.clock()

    def close_originals_allowed(self):
        self.close_checks += 1
        return True  # HOST close-control permission, not device/Owner proof.


class ReceiveStartupCollectorTests(unittest.TestCase):
    def test_expiry_pure_constructor_failure_and_independent_close(self):
        fixture, collector_raw, sources, paths, pins = frozen_inputs()
        running = types.ModuleType(RUNNING_NAME)
        running.__file__ = str(ROOT / fixture.EXECUTOR_PATH)
        startup = types.ModuleType(COLLECTOR_NAME)
        startup.__file__ = str(ROOT / COLLECTOR_PATH)
        canonical = {name: types.ModuleType(name) for name in fixture.NAMES}
        completed, live_calls = [], []
        def forbidden_io(*unused_args, **unused_kwargs):
            live_calls.append('HOST forbidden actual IO')
            raise AssertionError('HOST collector attempted actual IO')
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules,
                dict(canonical, **{RUNNING_NAME: running, COLLECTOR_NAME: startup})))
            for target in ('subprocess.Popen', 'socket.socket', 'os.fork', 'os.kill',
                           'os.waitpid', 'os.open', 'os.read', 'os.write', 'os.close',
                           'os.stat', 'os.lstat', 'os.readlink', 'os.urandom',
                           'os.system', 'threading.Thread.start'):
                stack.enter_context(mock.patch(target, side_effect=forbidden_io,
                                               create=True))
            exec(compile(dict(sources)['mta_client_executor'], running.__file__, 'exec'),
                 running.__dict__)
            modules = running._import_verified_sources(sources, paths, pins, running,
                                                       _retained_modules={})
            exec(compile(collector_raw, startup.__file__, 'exec'), startup.__dict__)
            self.assertEqual(set(fixture.NAMES), set(modules))
            self.assertIs(modules['mta_client_executor'], running)
            for name, original in canonical.items(): self.assertIs(sys.modules[name], original)

            # 1. The actual full collection constructor/run records the original
            # expiry. Nothing entered IO; close control cannot replace it.
            expired_scope = _HostScopeModel(modules, time.monotonic() - 1.0,
                fixture.MANIFEST_SHA, {'baseline_manifest': (), 'status_manifest': {}})
            with self.assertRaises(startup.StartupReadError) as expired_error:
                startup.collect(expired_scope)
            expired = expired_scope.collector_ticket['returned']
            self.assertIs(type(expired), startup.StartupCollection)
            self.assertEqual('startup_deadline', expired_error.exception.code)
            self.assertIs(expired.failure, expired_error.exception)
            self.assertIs(expired_scope.collector_ticket['failure'], expired_error.exception)
            self.assertIs(expired_scope.collector_ticket['ended'], True)
            self.assertIs(expired.ended, True)
            self.assertIs(expired.io_started, False)
            self.assertIs(expired._io_started_original, False)
            self.assertEqual([], expired.constructor_rows)
            self.assertEqual([], expired.reader_rows)
            self.assertEqual([], expired.status_rows)
            self.assertIsNone(expired.snapshot)
            self.assertIsNone(expired.close_failure)
            self.assertEqual([], expired.close_failures)
            self.assertIs(expired.close_attempted, True)
            self.assertIs(expired.resources_closed(), True)
            self.assertIs(expired.success, False)
            self.assertEqual([], live_calls)
            completed.append('actual_initial_expiry_preserved_known_no_io')

            # 2. Actual Store/ResourceBudget/ProcReader and IO adapter constructors
            # run purely. Invalid Baseline manifest fails its original initializer
            # before any collection, preserving the partial and exception.
            invalid_scope = _HostScopeModel(modules, time.monotonic() + 30.0,
                fixture.MANIFEST_SHA, {'baseline_manifest': (), 'status_manifest': {}})
            with mock.patch.object(os, 'urandom', return_value=b'0' * 16) as token_model:
                with self.assertRaises(modules['mta_client_baseline'].BaselineError) as ctor_error:
                    startup.collect(invalid_scope)
                self.assertEqual([mock.call(16)], token_model.call_args_list)
            failed = invalid_scope.collector_ticket['returned']
            self.assertIs(type(failed), startup.StartupCollection)
            self.assertEqual('invalid_manifest', ctor_error.exception.code)
            self.assertIs(failed.failure, ctor_error.exception)
            self.assertIs(invalid_scope.collector_ticket['failure'], ctor_error.exception)
            self.assertIs(invalid_scope.collector_ticket['ended'], True)
            self.assertIs(failed.io_started, False)
            self.assertIs(failed._io_started_original, False)
            self.assertEqual(['store', 'io', 'proc', 'baseline'],
                             [row['kind'] for row in failed.constructor_rows])
            self.assertTrue(all(row['started'] is True and row['ended'] is True
                                for row in failed.constructor_rows))
            self.assertTrue(all(row['returned'] is True and row['failure'] is None
                                for row in failed.constructor_rows[:-1]))
            partial = failed.constructor_rows[-1]
            self.assertIs(partial['returned'], False)
            self.assertIs(partial['failure'], ctor_error.exception)
            self.assertIs(type(partial['value']), failed._native_class)
            self.assertIs(partial['class'], failed._native_class)
            self.assertIs(partial['initializer'],
                          modules['mta_client_baseline'].BaselineCollector.__init__)
            self.assertIsNone(failed.collector)
            self.assertIs(type(failed.store), modules['mta_client_store'].DurableClientInitStore)
            self.assertIs(type(failed.budget), modules['mta_client_resource_budget'].ResourceBudget)
            self.assertIs(type(failed.store._identity), modules['mta_p2p_client_init'].Identity)
            self.assertIs(failed.store._resource_budget_v23, failed.budget)
            self.assertIs(failed.budget._store, failed.store)
            self.assertIs(failed.budget._provider, None)
            self.assertEqual(1, len(failed.reader_rows))
            original_reader = failed.reader_rows[0]['value']
            self.assertIs(type(original_reader), modules['mta_client_proc'].ProcReader)
            self.assertIs(failed.reader_rows[0]['bound'], True)
            self.assertEqual(2, len(failed.budget._readers))
            self.assertIs(failed.budget._readers[0], failed.store._proc_reader)
            self.assertIs(failed.budget._readers[1], original_reader)
            self.assertTrue(all(reader.history_closed() is True and reader._history == []
                                for reader in failed.budget._readers))
            self.assertEqual([], failed.budget._rows)
            self.assertEqual([], failed.status_rows)
            self.assertIsNone(failed.snapshot)
            self.assertIsNone(failed.close_failure)
            self.assertEqual([], failed.close_failures)
            self.assertIs(failed.close_attempted, True)
            self.assertIs(failed.resources_closed(), True)
            self.assertIs(failed.store._attempted, False)
            self.assertIs(failed.store._opened, False)
            self.assertIs(failed.success, False)
            self.assertEqual([], live_calls)
            completed.append('actual_pure_ctors_invalid_baseline_partial_preserved_closed')

            # 3. CLOSE-CONTROL MODEL ONLY. Captured original definition slots
            # are replaced before full StartupCollection construction. Synthetic
            # objects carry no real FDs, sockets, snapshots or successful reads.
            # The first close raises, but independent later closes must still run.
            events = []
            first_error = RuntimeError('HOST close-control first error')
            reader_model = types.SimpleNamespace(_rights=[])
            file_one_model, file_two_model = object(), object()
            source_model = types.SimpleNamespace(_files=(file_one_model, file_two_model))
            baseline_model = types.SimpleNamespace(_tickets=[])
            def reader_close_model(original):
                self.assertIs(original, reader_model)
                events.append('reader')
                raise first_error
            def files_close_model(original):
                self.assertTrue(original is file_one_model or original is file_two_model)
                events.append('file1' if original is file_one_model else 'file2')
                return True  # Only a model return, never real FD closure.
            def baseline_close_model(original):
                self.assertIs(original, baseline_model)
                events.append('baseline')
                return True  # Only close-control coverage.
            close_scope = _HostScopeModel(modules, time.monotonic() + 30.0,
                fixture.MANIFEST_SHA, {'baseline_manifest': (), 'status_manifest': {}})
            wpa, baseline = modules['mta_client_wpa_status'], modules['mta_client_baseline']
            with mock.patch.object(wpa.AuthenticatedStatusReader, '_close', reader_close_model), \
                    mock.patch.object(wpa._ReadFiles, 'close', files_close_model), \
                    mock.patch.object(baseline.BaselineCollector, 'close', baseline_close_model):
                close_only = startup.StartupCollection(close_scope)
                close_scope.collector_ticket = {'creator': startup.StartupCollection,
                    'returned': close_only, 'started': True, 'ended': True, 'failure': None}
                close_only.ended = close_only.attempted = True
                # Synthetic IO-entry flags exercise only the closing branch;
                # no actual run, Baseline/Status result or admission is forged.
                close_only.io_started = close_only._io_started_original = True
                close_only.status_rows.append({'source': source_model, 'reader': reader_model,
                                               'value': None, 'failure': None})
                close_only.collector = close_only._collector_original = baseline_model
                self.assertIs(close_only.close_originals(), False)
                self.assertEqual(['reader', 'file1', 'file2', 'baseline'], events)
                self.assertIs(close_only.close_failure, first_error)
                self.assertEqual(1, len(close_only.close_failures))
                self.assertIs(close_only.close_failures[0], first_error)
                self.assertIs(close_only.close_attempted, True)
                self.assertIs(close_only.resources_closed(), False)
                self.assertIsNone(close_only.snapshot)
                self.assertIs(close_only.success, False)
                self.assertIsNone(close_only.failure)
                self.assertIs(close_only.close_originals(), False)
                self.assertEqual(['reader', 'file1', 'file2', 'baseline'], events)
                self.assertEqual(1, len(close_only.close_failures))
            completed.append('model_independent_close_first_error_and_no_retry')
            self.assertIs(expired.resources_closed(), True)
            self.assertIs(failed.resources_closed(), True)
            self.assertEqual([], live_calls)
            for name, original in canonical.items(): self.assertIs(sys.modules[name], original)

        self.assertEqual([
            'actual_initial_expiry_preserved_known_no_io',
            'actual_pure_ctors_invalid_baseline_partial_preserved_closed',
            'model_independent_close_first_error_and_no_retry',
        ], completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    suite = unittest.TestSuite([ReceiveStartupCollectorTests(
        'test_expiry_pure_constructor_failure_and_independent_close')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
