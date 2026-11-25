"""One bounded HOST fixture for the actual new QML receipt parser, no device.

This checks refusal and scalar parsing only. Fixtures never prove an actual
click, page, RF action, restoration or phone transfer.
"""
import ast
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import traceback
import types
import unittest
import zipfile

BASE = Path(__file__).resolve().parents[1]
SOURCE = ('host/device_formal_receive_filecenter_navigation_anchor_v1_check.py',
          24423, '0e9f182b8ff01d8de0020fb3513ddd7b08fd4a33d0d58b10e62543d0ce559e42')
OBSERVED = ('ready_observed', 'button_ready_observed', 'cancel_confirmed_observed',
            'fresh_status_approved_observed', 'files_page_observed',
            'received_listing_observed', 'stable_observed')
ABSENT = ('business_start_action_issued', 'file_opened', 'media_played',
          'restoration_verified')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed_parser():
    raw = (BASE / SOURCE[0]).read_bytes()
    need(SOURCE[1] > 0 and (len(raw), hashlib.sha256(raw).hexdigest()) == SOURCE[1:],
         'actual_parser_source_pin')
    tree = ast.parse(raw)
    rows = [row for row in tree.body if isinstance(row, ast.FunctionDef) and
            row.name == 'navigation_receipt']
    need(len(rows) == 1, 'actual_parser_function')
    # The actual function only; no HOST main, runtime graph or target input.
    module = types.ModuleType('actual_navigation_receipt_v1_fixture')
    module.__dict__.update(json=json, re=re, need=need)
    exec(compile(ast.fix_missing_locations(ast.Module(body=rows, type_ignores=[])),
                 str(BASE / SOURCE[0]), 'exec'), module.__dict__)
    return raw, module.navigation_receipt


def success():
    row = dict(schema='navigation_qttest_v1', outcome='pass',
               code='received_page_stable', click_count=1)
    row.update((key, True) for key in OBSERVED)
    row.update((key, False) for key in ABSENT)
    return row


def frame(row, prefix=b'qml: ', suffix=b'\n'):
    return prefix + b'P011_MTA NAVIGATION_QTTEST_V1 ' + json.dumps(
        row, separators=(',', ':')).encode('ascii') + suffix


class ActualReceiptContract(unittest.TestCase):
    def test_fixed_success_and_refusals(self):
        raw, parser = fixed_parser()
        digest = hashlib.sha256(raw).hexdigest()
        good = success()
        for label, item in (('qml', frame(good)), ('plain', frame(good, b'')),
                            ('crcrlf', frame(good, suffix=b'\r\r\n')),
                            ('ansi', frame(good, b'\x1b[32mqml: \x1b[0m'))):
            with self.subTest(accept=label):
                self.assertEqual(parser(item), good)
        denied = [('empty', b''), ('missing', b'qml: ordinary page event\n'),
                  ('truncated', frame(good, suffix=b'')),
                  ('duplicate_frame', frame(good) + frame(good)),
                  ('extra_marker', frame(good) + b'P011_MTA NAVIGATION_QTTEST_V1 \n'),
                  ('unknown_prefix', frame(good, b'unrelated: ')),
                  ('too_large', b'x' * (4194304 + 1)),
                  ('json_null', b'P011_MTA NAVIGATION_QTTEST_V1 null\n'),
                  ('json_invalid', b'P011_MTA NAVIGATION_QTTEST_V1 {\n')]
        for key, value in (('schema', 'other'), ('outcome', 'fail'),
                           ('code', 'files_timeout'), ('click_count', 0),
                           ('click_count', True), ('click_count', 1.0),
                           ('click_count', '1')):
            row = dict(good); row[key] = value
            denied.append(('wrong_' + key + '_' + repr(value), frame(row)))
        for key in OBSERVED:
            row = dict(good); row[key] = False
            denied.append(('missing_event_' + key, frame(row)))
        for key in ABSENT:
            row = dict(good); row[key] = True
            denied.append(('forbidden_' + key, frame(row)))
        for key in tuple(good):
            row = dict(good); del row[key]
            denied.append(('missing_key_' + key, frame(row)))
        row = dict(good); row['unknown'] = False
        denied.append(('unknown_field', frame(row)))
        row = dict(good); row['ready_observed'] = 1
        denied.append(('integer_not_bool', frame(row)))
        duplicate = frame(good).replace(b'{', b'{"click_count":0,', 1)
        denied.append(('duplicate_json_key', duplicate))
        for label, item in denied:
            with self.subTest(refuse=label):
                with self.assertRaises((ValueError, TypeError)):
                    parser(item)
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), SOURCE[1:])
        self.assertEqual(digest, hashlib.sha256((BASE / SOURCE[0]).read_bytes()).hexdigest())


def main():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('navigation-receipt-v1-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(passed=False, device_invoked=False, fixture_only=True,
                  actual_gui_event_verified=False, phone_tested=False,
                  source_preserved=False, tests_run=0, error_kind=None)
    stream = io.StringIO()
    try:
        raw, unused = fixed_parser()
        private = out / 'private-inputs'; private.mkdir()
        (private / 'actual-host-source.py').write_bytes(raw)
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.TestSuite((ActualReceiptContract('test_fixed_success_and_refusals'),)))
        report.update(tests_run=result.testsRun, source_preserved=(BASE / SOURCE[0]).read_bytes() == raw,
                      failures=len(result.failures), errors=len(result.errors))
        report['passed'] = result.wasSuccessful() and report['source_preserved']
    except BaseException as error:
        report['error_kind'] = type(error).__name__
        stream.write(traceback.format_exc())
    (out / 'host.stdout.raw').write_bytes(stream.getvalue().encode('utf-8'))
    (out / 'host.stderr.raw').write_bytes(b'')
    code = 0 if report['passed'] else 1
    (out / 'host.exit').write_bytes((str(code) + '\n').encode('ascii'))
    encoded = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One actual HOST parser method with bounded fixtures only.\n'
              b'No old suite, HOST main, runtime graph, ADB, GUI, RF or phone runs.\n'
              b'Fixture acceptance is not actual click/page/restoration evidence.\n')
    (out / 'result.json').write_bytes(encoded)
    (out / 'README.txt').write_bytes(readme)
    path = out / 'public-result.zip'
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', encoded); archive.writestr('README.txt', readme)
    with zipfile.ZipFile(path) as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == encoded and archive.read('README.txt') == readme,
             'public_zip_readback')
    print(json.dumps(dict(report, result_dir=str(out), public_result_zip=str(path),
                          zip_sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
