"""One HOST-only startup-failure contract; default SOURCE, explicit --check-host.

Only the second real reader Thread.start is made to raise a retained RuntimeError.
The Popen child and first reader are real. No ADB, device mock, old suite, or target
operation is performed. Partial stdout stays raw; missing stderr is not invented.
"""
import argparse
import ast
import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
import traceback
import types
import unittest
import zipfile


BASE = Path(__file__).resolve().parents[1]
STREAM = BASE / 'host/ready_capture_stream_v2.py'
STREAM_SIZE = 8040
STREAM_SHA = '1dbac1b1c4c164b84f53b323acdace78175b00d838229df0251af9c7a596dc9b'
PREFIX = b'host_startup_partial\x00\r\r\n'
CHILD = (
    "import os,time\n"
    "os.write(1,b'host_startup_partial\\x00\\r\\r\\n')\n"
    "os.write(2,b'unstarted_reader_stderr\\xff\\n')\n"
    "time.sleep(30)\n")
ACTIVE = None


def save(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('short_write')


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class ReadyCaptureStreamV2Contract(unittest.TestCase):
    def test_actual_second_reader_start_failure_reaps_original_host_child(self):
        stream, private, observed = ACTIVE
        directory = private / 'second-reader-start-failure'
        directory.mkdir()
        original_subprocess = stream.subprocess
        original_threading = stream.threading
        argv = [sys.executable, '-I', '-B', '-c', CHILD]
        children, created, started, joined = [], [], [], []
        fault = RuntimeError('host_second_reader_start_fault')
        injection = dict(attempted=False, first_reader_running=False,
            exact_host_child_running=False, partial_stdout_observed=False)

        class HostChildReceipt:
            def __getattr__(self, name):
                return getattr(subprocess, name)

            def Popen(self, actual_argv, **kwargs):
                if actual_argv != argv or kwargs.get('shell', False):
                    raise ValueError('nonfixed_local_child')
                child = subprocess.Popen(actual_argv, **kwargs)
                children.append(child)
                return child

        class InjectedStartThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

            def start(self):
                if self.name == 'host-carrier-raw-1':
                    injection['attempted'] = True
                    until = time.monotonic() + 2
                    while time.monotonic() < until:
                        first = [row for row in started if row.name == 'host-carrier-raw-0']
                        injection['first_reader_running'] = len(first) == 1 and first[0].is_alive()
                        injection['exact_host_child_running'] = len(children) == 1 and children[0].poll() is None
                        path = directory / 'child.stdout.raw'
                        if path.is_file() and path.stat().st_size == len(PREFIX):
                            injection['partial_stdout_observed'] = True
                            break
                        time.sleep(.01)
                    # Raise the same original exception object, never a device mock.
                    raise fault
                super().start()
                started.append(self)

            def join(self, timeout=None):
                joined.append(self)
                return super().join(timeout=timeout)

        stream.subprocess = HostChildReceipt()
        stream.threading = types.SimpleNamespace(Thread=InjectedStartThread)
        error = None
        result = None
        began = time.monotonic()
        try:
            result = stream.run_stream(argv, directory, 'child', 5)
        except BaseException as caught:
            error = caught
        finally:
            stream.subprocess = original_subprocess
            stream.threading = original_threading
            observed.update(injection=injection, elapsed_seconds=round(time.monotonic() - began, 6),
                real_child_count=len(children), created_reader_count=len(created),
                started_reader_count=len(started), joined_reader_count=len(joined),
                only_started_threads_joined=all(row in started for row in joined),
                original_exception_preserved=error is fault,
                actual_exception_type=type(error).__name__ if error is not None else None,
                exact_host_child_exited=len(children) == 1 and children[0].poll() is not None,
                started_readers_closed=all(not row.is_alive() for row in started),
                retained_pipe_objects_closed=(len(children) == 1 and
                    all(pipe is None or pipe.closed for pipe in
                        (children[0].stdout, children[0].stderr, children[0].stdin))),
                stderr_raw_exists=(directory / 'child.stderr.raw').exists(), passed=False)
            for suffix in ('.stdout.raw', '.stderr.raw', '.host-exit'):
                path = directory / ('child' + suffix)
                if path.is_file():
                    observed[suffix[1:].replace('-', '_')] = identity(path.read_bytes())

        self.assertIs(error, fault)
        self.assertIsNone(result)
        self.assertEqual(len(children), 1)
        self.assertTrue(injection['attempted'])
        self.assertTrue(injection['first_reader_running'])
        self.assertTrue(injection['exact_host_child_running'])
        self.assertTrue(injection['partial_stdout_observed'])
        self.assertEqual(len(created), 2)
        self.assertEqual(len(started), 1)
        self.assertEqual(len(joined), 1)
        self.assertIs(joined[0], started[0])
        self.assertEqual(started[0].name, 'host-carrier-raw-0')
        self.assertFalse(started[0].is_alive())
        self.assertIsNone(created[1].ident, 'failed-start second reader unexpectedly started')
        self.assertIsNotNone(children[0].poll())
        self.assertNotEqual(children[0].returncode, 0)
        self.assertTrue(observed['retained_pipe_objects_closed'])
        self.assertEqual((directory / 'child.stdout.raw').read_bytes(), PREFIX)
        self.assertFalse((directory / 'child.stderr.raw').exists(), 'do not fabricate absent stderr')
        self.assertEqual((directory / 'child.host-exit').read_text(encoding='ascii'), 'TIMEOUT')
        observed['passed'] = True


def main():
    global ACTIVE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-host', action='store_true')
    args = parser.parse_args()
    mode = 'host' if args.check_host else 'source'
    out = BASE / 'results' / ('ready-capture-stream-v2-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = private / 'inputs'
    inputs.mkdir()
    report = dict(schema='p011-host-ready-stream-start-failure-v2', passed=False,
        evidence='ACTUAL_HOST_LOCAL_CHILD' if args.check_host else 'PC_SOURCE',
        device_invoked=False, adb_invoked=False, device_acceptance=False,
        target_input_injected=False, rf_requested=False, old_suite_invoked=False,
        v1_pass_retested=False, private_raw_in_public_zip=False,
        source_verified=False, tests_run=0, method_count=0, observed={})
    try:
        raw = STREAM.read_bytes()
        self_raw = Path(__file__).read_bytes()
        save(inputs / 'ready_capture_stream_v2.py', raw)
        save(inputs / 'test_ready_capture_stream_v2.py', self_raw)
        save(inputs / 'fixed-local-child.py', CHILD.encode('ascii'))
        report['stream_source'] = identity(raw)
        report['driver_source'] = identity(self_raw)
        if len(raw) != STREAM_SIZE or hashlib.sha256(raw).hexdigest() != STREAM_SHA:
            raise ValueError('stream_pin_changed')
        if len(self_raw) > 14 * 1024:
            raise ValueError('driver_budget')
        ast.parse(raw.decode('utf-8'), filename=str(STREAM))
        ast.parse(self_raw.decode('utf-8'), filename=__file__)
        ast.parse(CHILD, filename='fixed-local-child')
        report['source_verified'] = True
        if args.check_host:
            spec = importlib.util.spec_from_file_location('retained_host_ready_stream_v2', STREAM)
            stream = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(stream)
            ACTIVE = (stream, private, report['observed'])
            log = io.StringIO()
            suite = unittest.TestSuite([ReadyCaptureStreamV2Contract(
                'test_actual_second_reader_start_failure_reaps_original_host_child')])
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            save(private / 'host-contract.stdout.raw', b'')
            save(private / 'host-contract.stderr.raw', log.getvalue().encode('utf-8'))
            save(private / 'host-contract.host-exit', b'0' if result.wasSuccessful() else b'1')
            report.update(method_count=1, tests_run=result.testsRun,
                failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
                passed=(result.wasSuccessful() and result.testsRun == 1 and not result.skipped and
                    report['observed'].get('passed') is True))
        else:
            report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        save(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        ACTIVE = None
    save(out / 'result.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'))
    note = (
        'HOST-only: one real local Python child with second reader Thread.start failure.\n'
        'SOURCE is syntax/pins only. This is not P011, UI, RF or physical acceptance.\n'
        'Original partial stdout and host-exit remain private. An unstarted stderr\n'
        'reader has no fabricated raw file. No v1 PASS or old suite is replayed.\n')
    save(out / 'README.txt', note.encode('ascii'))
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(out / 'result.json', 'result.json')
        archive.write(out / 'README.txt', 'README.txt')
    print('RESULT_DIR=' + str(out), flush=True)
    print('PUBLIC_ZIP_SHA256=' + hashlib.sha256(bundle.read_bytes()).hexdigest(), flush=True)
    print('HOST_CONTRACT_PASSED=' + str(report['passed']), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
