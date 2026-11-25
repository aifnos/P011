"""Fixed HOST-only raw-stream contract; SOURCE default, one explicit HOST method.

Children are the current Python executable with -I -B -c and fixed local source.
No ADB, target input, candidate launch, RF, old suite, or device acceptance.
The callback observes only this execution's HOST process and HOST raw files.
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
import unittest
import zipfile


BASE = Path(__file__).resolve().parents[1]
STREAM = BASE / 'host/ready_capture_stream_v1.py'
STREAM_SIZE = 6690
STREAM_SHA = '0834b4bafd780562cdde847ef6fe0d1a5ed98318fbe00a87adf2a72b3232a34d'
READY = b'MTA_FORMAL_UI_READY'
ACTIVE = None


def save(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('short_write')


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def child_sources():
    """Fixed ASCII scripts; binary streams are generated, not personal input."""
    return {
        'exact_crcrlf': (
            "import os,time\n"
            "os.write(1,b'prefix\\x00\\xff\\r\\nMTA_FORMAL_UI_READY\\r\\r\\n')\n"
            "os.write(2,b'err\\x00\\xff\\r\\r\\n')\n"
            "time.sleep(.35)\n"
            "os.write(1,b'suffix\\r\\n')\n"),
        'fragmented_duplicate': (
            "import os,time\n"
            "for part in (b'MTA_FO',b'RMAL_UI_',b'READY\\r\\r',b'\\n'):\n"
            " os.write(1,part);time.sleep(.12)\n"
            "os.write(1,b'MTA_FORMAL_UI_READY\\n')\n"
            "time.sleep(.25)\n"),
        'substring_partial_stderr': (
            "import os\n"
            "os.write(1,b'XMTA_FORMAL_UI_READY\\nMTA_FORMAL_UI_READY_extra\\r\\nMTA_FORMAL_UI_READY')\n"
            "os.write(2,b'MTA_FORMAL_UI_READY\\r\\r\\n')\n"),
        'long_fragment_tail': (
            "import os,time\n"
            "r=b'MTA_FORMAL_UI_READY'\n"
            "os.write(1,b'P'*70000);time.sleep(.15)\n"
            "os.write(1,r+b'\\r'*(65536-len(r)));time.sleep(.15)\n"
            "os.write(1,b'\\n'+r+b'\\r\\n');time.sleep(.25)\n"),
        'dual_pipe_callback': (
            "import os,time\n"
            "os.write(1,b'MTA_FORMAL_UI_READY\\r\\r\\n');time.sleep(.12)\n"
            "a=b'A'*8192;b=b'B'*8192\n"
            "for unused in range(32):\n"
            " os.write(1,a);os.write(2,b)\n"
            "os.write(1,b'out_done\\x00\\n');os.write(2,b'err_done\\xff\\r\\n')\n"
            "time.sleep(.35)\n"),
        'stdin_complete': (
            "import os,sys\n"
            "data=sys.stdin.buffer.read()\n"
            "at=0\n"
            "while at<len(data):at+=os.write(1,data[at:])\n"
            "os.write(2,b'input_complete\\x00\\r\\r\\n')\n"),
        'nonzero': (
            "import os,sys\n"
            "os.write(1,b'nonzero_out\\x00\\r\\r\\n')\n"
            "os.write(2,b'nonzero_err\\xff\\n')\n"
            "sys.exit(7)\n"),
        'timeout': (
            "import os,time\n"
            "os.write(1,b'timeout_out\\x00\\r\\r\\n')\n"
            "os.write(2,b'timeout_err\\xff\\n')\n"
            "time.sleep(10)\n"),
    }


class HostChildReceipt:
    """Only retain real Popen results; no fake process or changed child options."""
    def __init__(self, code):
        self.argv = [sys.executable, '-I', '-B', '-c', code]
        self.children = []

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def Popen(self, argv, **kwargs):
        if argv != self.argv or kwargs.get('shell', False):
            raise ValueError('nonfixed_child')
        child = subprocess.Popen(argv, **kwargs)
        self.children.append(child)
        return child


class ReadyCaptureStreamV1Contract(unittest.TestCase):
    def test_actual_local_python_raw_stream_contract(self):
        stream, private, records, scripts = ACTIVE
        original_subprocess = stream.subprocess
        facts_keys = {
            'host_stream_complete', 'raw_readers_closed', 'stdin_writer_closed',
            'callback_closed', 'ready_stream_count', 'callback_failed',
            'stdout_bytes', 'stderr_bytes',
        }

        def run_case(name, stdout, stderr, ready_count=0, data=None,
                     expected_error=None, timeout=6, drain_callback=False):
            directory = private / name
            directory.mkdir()
            receipt = HostChildReceipt(scripts[name])
            callback_rows = []
            callback_started = threading.Event()
            stream.subprocess = receipt

            def on_ready():
                # No writes or target access: inspect the retained HOST child.
                row = dict(child_running_at_callback=(len(receipt.children) == 1 and
                    receipt.children[0].poll() is None), pipes_drained_while_callback=False)
                callback_rows.append(row)
                callback_started.set()
                if drain_callback:
                    until = time.monotonic() + 2
                    while time.monotonic() < until:
                        try:
                            out_size = (directory / 'child.stdout.raw').stat().st_size
                            err_size = (directory / 'child.stderr.raw').stat().st_size
                        except FileNotFoundError:
                            out_size, err_size = -1, -1
                        if out_size == len(stdout) and err_size == len(stderr):
                            row['pipes_drained_while_callback'] = True
                            return
                        time.sleep(.01)
                    raise AssertionError('callback_blocked_pipe_drain')

            output = None
            facts = None
            error = None
            started = time.monotonic()
            try:
                output, facts = stream.run_stream(receipt.argv, directory, 'child', timeout,
                    input_data=data, on_ready=on_ready)
            except stream.StreamError as caught:
                error = caught
            finally:
                stream.subprocess = original_subprocess
                elapsed = time.monotonic() - started
                row = dict(case=name, expected_error=expected_error,
                    actual_error=str(error) if error is not None else None,
                    elapsed_seconds=round(elapsed, 6), callback_count=len(callback_rows),
                    real_child_count=len(receipt.children),
                    exact_host_child_exited=(len(receipt.children) == 1 and
                        receipt.children[0].poll() is not None),
                    callbacks=callback_rows, stream_facts=facts, passed=False)
                records.append(row)
                for suffix in ('.stdout.raw', '.stderr.raw', '.host-exit'):
                    path = directory / ('child' + suffix)
                    if path.is_file():
                        row[suffix[1:].replace('-', '_')] = identity(path.read_bytes())

            self.assertEqual(len(receipt.children), 1)
            self.assertIsNotNone(receipt.children[0].poll(), 'retained host child still running')
            self.assertEqual((directory / 'child.stdout.raw').read_bytes(), stdout)
            self.assertEqual((directory / 'child.stderr.raw').read_bytes(), stderr)
            host_exit = (directory / 'child.host-exit').read_text(encoding='ascii')
            if expected_error is not None:
                self.assertIsInstance(error, stream.StreamError)
                self.assertEqual(str(error), expected_error)
                self.assertIsNone(output)
                self.assertIsNone(facts)
                self.assertEqual(host_exit, 'TIMEOUT' if name == 'timeout' else '7')
                if name == 'nonzero':
                    self.assertEqual(receipt.children[0].returncode, 7)
                else:
                    self.assertNotEqual(receipt.children[0].returncode, 0)
            else:
                self.assertIsNone(error)
                self.assertEqual(host_exit, '0')
                self.assertEqual(output, stdout)
                self.assertEqual(set(facts), facts_keys)
                for key in ('host_stream_complete', 'raw_readers_closed',
                            'stdin_writer_closed', 'callback_closed'):
                    self.assertIs(facts[key], True)
                self.assertIs(facts['callback_failed'], False)
                self.assertIs(type(facts['ready_stream_count']), int)
                self.assertEqual(facts['ready_stream_count'], ready_count)
                self.assertEqual(facts['stdout_bytes'], len(stdout))
                self.assertEqual(facts['stderr_bytes'], len(stderr))
            self.assertEqual(len(callback_rows), 1 if ready_count else 0)
            self.assertEqual(callback_started.is_set(), bool(ready_count))
            for observed in callback_rows:
                self.assertIs(observed['child_running_at_callback'], True)
                if drain_callback:
                    self.assertIs(observed['pipes_drained_while_callback'], True)
            row['passed'] = True

        run_case('exact_crcrlf',
            b'prefix\x00\xff\r\n' + READY + b'\r\r\nsuffix\r\n',
            b'err\x00\xff\r\r\n', ready_count=1)
        run_case('fragmented_duplicate', READY + b'\r\r\n' + READY + b'\n',
            b'', ready_count=2)
        run_case('substring_partial_stderr',
            b'X' + READY + b'\n' + READY + b'_extra\r\n' + READY,
            READY + b'\r\r\n')
        run_case('long_fragment_tail', b'P' * 70000 + READY +
            b'\r' * (65536 - len(READY)) + b'\n' + READY + b'\r\n',
            b'', ready_count=1)
        run_case('dual_pipe_callback', READY + b'\r\r\n' + b'A' * 262144 +
            b'out_done\x00\n', b'B' * 262144 + b'err_done\xff\r\n',
            ready_count=1, drain_callback=True)
        input_bytes = bytes(range(256)) * 1024
        run_case('stdin_complete', input_bytes, b'input_complete\x00\r\r\n',
            data=input_bytes)
        run_case('nonzero', b'nonzero_out\x00\r\r\n', b'nonzero_err\xff\n',
            expected_error='host_stream_exit')
        run_case('timeout', b'timeout_out\x00\r\r\n', b'timeout_err\xff\n',
            expected_error='host_stream_timeout', timeout=.75)


def main():
    global ACTIVE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-host', action='store_true',
        help='Run exactly one fixed HOST-only method using real local Python children')
    args = parser.parse_args()
    mode = 'host' if args.check_host else 'source'
    out = BASE / 'results' / ('ready-capture-stream-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = private / 'inputs'
    inputs.mkdir()
    report = dict(schema='p011-host-ready-capture-stream-contract-v1', passed=False,
        evidence='ACTUAL_HOST_LOCAL_CHILD' if args.check_host else 'PC_SOURCE',
        device_invoked=False, adb_invoked=False, target_input_injected=False,
        rf_requested=False, device_acceptance=False, old_suite_invoked=False,
        source_verified=False, method_count=0, tests_run=0,
        private_raw_in_public_zip=False, cases=[])
    try:
        raw = STREAM.read_bytes()
        self_raw = Path(__file__).read_bytes()
        save(inputs / 'ready_capture_stream_v1.py', raw)
        save(inputs / 'test_ready_capture_stream_v1.py', self_raw)
        report['stream_source'] = identity(raw)
        report['driver_source'] = identity(self_raw)
        if len(raw) != STREAM_SIZE or hashlib.sha256(raw).hexdigest() != STREAM_SHA:
            raise ValueError('stream_pin_changed')
        if len(self_raw) > 18 * 1024:
            raise ValueError('driver_budget')
        ast.parse(raw.decode('utf-8'), filename=str(STREAM))
        ast.parse(self_raw.decode('utf-8'), filename=__file__)
        scripts = child_sources()
        if len(scripts) != 8 or sum(len(code.encode('ascii')) for code in scripts.values()) > 8192:
            raise ValueError('fixed_child_budget')
        for name, code in scripts.items():
            ast.parse(code, filename='fixed-host-child-' + name)
            save(inputs / ('child-' + name + '.py'), code.encode('ascii'))
        report['source_verified'] = True
        report['fixed_child_count'] = len(scripts)
        if args.check_host:
            spec = importlib.util.spec_from_file_location('retained_host_ready_stream_v1', STREAM)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if module.READY != READY or module.MAX_CAPTURED_BYTES != 8388608:
                raise ValueError('stream_constants_changed')
            records = report['cases']
            ACTIVE = (module, private, records, scripts)
            log = io.StringIO()
            suite = unittest.TestSuite([ReadyCaptureStreamV1Contract(
                'test_actual_local_python_raw_stream_contract')])
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
            save(private / 'host-contract.stderr.raw', log.getvalue().encode('utf-8'))
            save(private / 'host-contract.stdout.raw', b'')
            save(private / 'host-contract.host-exit', b'0' if result.wasSuccessful() else b'1')
            report.update(method_count=1, tests_run=result.testsRun,
                failures=len(result.failures), errors=len(result.errors),
                skipped=len(result.skipped), passed=(result.wasSuccessful() and
                    result.testsRun == 1 and not result.skipped and len(records) == 8 and
                    all(row['passed'] for row in records)))
        else:
            report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        save(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        ACTIVE = None
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    save(out / 'result.json', public)
    note = (
        'HOST-only stream contract. SOURCE means syntax/pins only. CHECK uses fixed\n'
        'current Python local children, not P011, UI, RF, or physical input.\n'
        'Original stdout/stderr/host-exit and local inputs remain in private-raw.\n'
        'The public ZIP contains only this readme and metadata result.json.\n'
        'No old suite, bundled candidate, startup, or device status is accepted here.\n')
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
