"""One HOST-only method: real receipt collector faults, no graph/main/phone.

Select the actual frozen collector AST. Exercise three receipt-read OSError
locations with known/unknown initial observations in new project-owned dirs.
Use the actual pinned InputEvidence/fresh/sealer and retain all failure cases.
"""
import ast
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import tempfile
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/phone_handoff_durable_window_receipt_fault_v1_check.py'
CMD = 'HOST_MTA_PHONE_HANDOFF_DURABLE_WINDOW_RECEIPT_FAULT_V1_CHECK.cmd'
WRAPPER = ('host/device_phone_handoff_durable_window_v1_check.py', 32689,
    'f0c95bb94ee5f7e4a247f4aa38e41be2a3780a31a585dde431884b5017b1bd38')
SOURCE_WRAPPER = ('results/phone-handoff-durable-window-v1-source-20261006-021459-eb8adf45/private-inputs/host/device_phone_handoff_durable_window_v1_check.py',
    31365, 'b8748194c5a5cbd2a72e74143515099a5a0936821374dc85549a7970cc4b2910')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
    '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
README = (b'One new HOST-only actual collect_receipts method contract, no graph/main/phone.\n'
    b'Three receipt read OSError sites times two known/unknown initial observations.\n'
    b'Original ValueError and COMPONENT fixture retained; incomplete receipt is FAIL.\n'
    b'Known earlier parsed remote fixture remains, unknown initial status cannot create0.\n'
    b'Actual pinned fresh/InputEvidence/private-first sealer; input snapshots and private\n'
    b'SOURCE/result ZIP CRC/member readback for each failure case.\n'
    b'Whole wrapper AST inverse removes only the new collector and restores its former\n'
    b'four finally receipt nodes; graph/carrier functions and phone phases unchanged.\n'
    b'No project runtime, ADB, RF, archived main/suite, old SOURCE or carrier builder executes.\n'
    b'New project-owned temporary case directories remain private evidence, not device logs.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def shape(node):
    return ast.dump(node, include_attributes=False)


def fixed(inputs, pin):
    raw = (BASE / pin[0]).read_bytes()
    inputs[pin[0]] = raw
    need((len(raw), digest(raw)) == pin[1:], 'actual_input_pin')
    return raw


def verify_host_only_delta(previous, current):
    before, after = ast.parse(previous), ast.parse(current)
    original_main = [row for row in before.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    selected_main = [row for row in after.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    collectors = [row for row in after.body if isinstance(row, ast.FunctionDef) and row.name == 'collect_receipts']
    need(len(original_main) == len(selected_main) == len(collectors) == 1, 'actual_delta_functions')
    original_try = [row for row in original_main[0].body if isinstance(row, ast.Try) and row.finalbody]
    selected_try = [row for row in selected_main[0].body if isinstance(row, ast.Try) and row.finalbody]
    need(len(original_try) == len(selected_try) == 1 and len(original_try[0].finalbody) == 5 and
         len(selected_try[0].finalbody) == 2, 'finally_receipt_shape')
    call = ast.parse('collect_receipts(private, report, sealer.fresh if sealer is not None else None)').body[0]
    need(shape(selected_try[0].finalbody[0]) == shape(call) and
         shape(selected_try[0].finalbody[1]) == shape(original_try[0].finalbody[4]), 'receipt_only_dispatch')
    selected_try[0].finalbody[:1] = copy.deepcopy(original_try[0].finalbody[:4])
    after.body.remove(collectors[0])
    need(shape(before) == shape(after), 'whole_host_ast_inverse')


def select_collector(raw):
    tree = ast.parse(raw)
    names = ('need', 'digest', 'collect_receipts')
    nodes = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in names]
    need(tuple(row.name for row in nodes) == names and all(not row.decorator_list for row in nodes),
         'actual_collector_selector')
    module = types.ModuleType('actual_receipt_collector_only')
    module.__dict__.update(Path=Path, re=re, hashlib=hashlib, traceback=traceback)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BASE / WRAPPER[0]), 'exec'), module.__dict__)
    need('main' not in module.__dict__ and 'compose' not in module.__dict__, 'no_main_or_carrier_builder')
    return module


def source_zip(sealer, out, inputs):
    members = {'private-inputs/'+name: raw for name, raw in sorted(inputs.items())}
    path = out / 'private-source.zip'
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    sha = sealer._verify_zip(path, members)
    return dict(private_source_zip_readback=True, private_source_zip_sha256=sha,
                private_source_zip_bytes=path.stat().st_size)


def test_receipt_read_faults(sealer, raw, inputs, cases_root):
    """The sole test method, six finite scenarios, actual collector and seal."""
    rows = []
    for receipt in ('stdout', 'stderr', 'host-exit'):
        for earlier_known in (False, True):
            case_out = Path(tempfile.mkdtemp(prefix=receipt+'-', dir=str(cases_root)))
            need(case_out.resolve().parent == cases_root.resolve(), 'owned_temporary_case')
            private = case_out / 'private-raw'; private.mkdir()
            prefix = private / '01-phone-discovery'
            receipts = {'stdout': (Path(str(prefix)+'.stdout.raw'), b'MTA_REMOTE_EXIT=0\n'),
                        'stderr': (Path(str(prefix)+'.stderr.raw'), b''),
                        'host-exit': (Path(str(prefix)+'.host-exit'), b'0\n')}
            for path, value in receipts.values():
                sealer.fresh(path, value)
            fault = receipts[receipt][0]

            class FaultPath:
                def __init__(self, value):
                    self.path = Path(value)

                def exists(self):
                    return self.path.exists()

                def read_bytes(self):
                    if self.path == fault:
                        raise PermissionError('injected_receipt_'+receipt)
                    return self.path.read_bytes()

                def read_text(self, **kwargs):
                    if self.path == fault:
                        raise PermissionError('injected_receipt_'+receipt)
                    return self.path.read_text(**kwargs)

            collector = select_collector(raw)
            collector.Path = FaultPath
            component = {'complete': False, 'reason': 'fixture'} if earlier_known else None
            report = dict(schema='receipt-fault-fixture-v1', passed=True, error='ValueError',
                remote_exit=1 if earlier_known else 'UNKNOWN', remote_status_known=earlier_known,
                component=component, host_exit='NOT_RUN', fixture_only=True)
            returned = collector.collect_receipts(private, report, sealer.fresh)
            need(returned is False and report['passed'] is False and report['error'] == 'ValueError' and
                 report['receipt_error'] == 'PermissionError' and report['receipt_readback_verified'] is False and
                 report['component'] is component and report['remote_exit'] == (1 if earlier_known else 'UNKNOWN') and
                 report['remote_status_known'] is earlier_known, 'actual_receipt_fault_semantics')
            diagnostic = (private / 'receipt-error.private.txt').read_bytes()
            need(b'PermissionError' in diagnostic and ('injected_receipt_'+receipt).encode('ascii') in diagnostic,
                 'actual_private_receipt_error')
            evidence = sealer.InputEvidence(dict(inputs))
            evidence.snapshot(case_out, lambda name: name)
            need(all((case_out/'private-inputs'/name).read_bytes() == value for name, value in inputs.items()),
                 'actual_failure_input_snapshot')
            report.update(source_zip(sealer, case_out, inputs))
            report['source_preserved'] = True
            sealed = sealer.seal_result(case_out, report, b'Finite HOST receipt fault fixture; not device evidence.\n')
            need(sealed['host_exit'] == 1 and sealed['report']['passed'] is False and sealed['archive'] is not None,
                 'false_private_first_result_sealed')
            with zipfile.ZipFile(sealed['archive']) as archive:
                need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None,
                     'case_public_zip_readback')
                public = json.loads(archive.read('result.json'))
                need(public == sealed['report'] and public['passed'] is False and public['error'] == 'ValueError' and
                     public['remote_exit'] == (1 if earlier_known else 'UNKNOWN') and
                     public['receipt_readback_verified'] is False, 'case_false_verdict_readback')
            private_members = {'result.json': (case_out/'private-seal/result.json').read_bytes(),
                               'README.txt': (case_out/'private-seal/README.txt').read_bytes()}
            private_result_sha = sealer._verify_zip(case_out/'private-seal/candidate-result.zip', private_members)
            rows.append(dict(receipt=receipt, earlier_known_fixture=earlier_known,
                original_error_preserved=True, component_observation_preserved=True,
                unknown_never_fabricated_zero=True, incomplete_receipt_is_fail=True,
                actual_input_snapshot=True, private_source_zip_readback=True,
                private_result_zip_readback=True, private_result_zip_sha256=private_result_sha,
                public_false_zip_sha256=sealed['archive_sha256']))
    need(len(rows) == 6, 'bounded_three_faults_two_initial_states')
    return rows


def main():
    need(not sys.argv[1:] and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_host_contract')
    out = BASE / 'results' / ('phone-handoff-durable-window-receipt-fault-v1-host-'+
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs = {}
    sealer_raw = fixed(inputs, SEALER)
    sealer = types.ModuleType('actual_receipt_fault_private_first_sealer')
    exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), sealer.__dict__)
    report = dict(schema='p011-phone-handoff-durable-window-receipt-fault-v1-host', mode='host',
        passed=False, error=None, test_methods_run=0, case_count=0, device_invoked=False,
        graph_executed=False, carrier_builder_executed=False, archived_main_called=False,
        old_suite_executed=False, rf_requested=False, phone_requested=False, carrier_bytes_changed=False,
        input_snapshot_verified=False, host_only_ast_inverse_verified=False, temporary_cases_retained=True)
    try:
        current, previous = fixed(inputs, WRAPPER), fixed(inputs, SOURCE_WRAPPER)
        for name in (SELF, CMD):
            inputs[name] = (BASE/name).read_bytes()
        verify_host_only_delta(previous, current)
        report['host_only_ast_inverse_verified'] = True
        cases_root = out / 'private-cases'; cases_root.mkdir()
        report['test_methods_run'] = 1
        report['cases'] = test_receipt_read_faults(sealer, current, inputs, cases_root)
        report['case_count'] = len(report['cases'])
        report['passed'] = True
    except BaseException as failure:
        report['error'] = type(failure).__name__
        report['passed'] = False
        sealer.fresh(private/'host-error.private.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            evidence = sealer.InputEvidence(inputs)
            evidence.snapshot(out, lambda name: name)
            need(all((BASE/name).read_bytes() == value and
                     (out/'private-inputs'/name).read_bytes() == value for name, value in inputs.items()),
                 'actual_host_inputs_preserved')
            report['input_snapshot_verified'] = True
            report.update(source_zip(sealer, out, inputs))
        except BaseException as failure:
            report['passed'] = False
            report['error'] = report['error'] or type(failure).__name__
            sealer.fresh(private/'evidence-error.private.txt', traceback.format_exc().encode('utf-8'))
    report['input_pins'] = [dict(path=name, bytes=len(value), sha256=digest(value))
                            for name, value in inputs.items()]
    sealed = sealer.seal_result(out, report, README)
    print(json.dumps(dict(passed=sealed['report']['passed'], result_dir=str(out),
        public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
