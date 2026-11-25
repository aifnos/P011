"""Thin exclusive 19-asset UI-v5 stage entry; default PC SOURCE only.

Only --stage-device may create/read back the new fixed absent asset session.
No UI, Boot, Owner, sender/receiver worker, credentials or radio is started.
The passed v4 sender root is neither restaged nor modified. Pinned HOST helper
definitions use their actual __file__; no old main/test/builder is invoked.
All target staging and original FD gates remain the existing fixed generator.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import traceback
import types
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_filecenter_ui_v5_assets_check.py'
CMD = 'STAGE_MTA_FORMAL_SEND_FILECENTER_UI_V5_ASSETS.cmd'
SESSION = 'a44b98dd639095d9063c9e1a'
BUNDLE = 'out/mta-ui-send-v5-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
COMMON = ('host/device_formal_send_filecenter_ui_v5_check.py', 26521,
          '9cc457accb6b7bdaa0555d9732a9d55a9d32e5cedee3b7403dc4693c2ca41650')
ASSET_HELPER = ('host/device_receive_filecenter_assets_v1_check.py', 46084,
                'cd5dc6cdf074a71d5309b1444e37c2fa0489c0fd5ca62e9fba9860eaa9f8c5e9')
CARRIER_HELPER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py', 25857,
                  '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
VALIDATOR = ('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py', 12526,
             'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 4227,
                  '80eaec304c785b5fa267f5ae2be49790413293fa49ec392420f8ef18a641f270')
ASSET_BYTES = 4184498


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'host_write')


def definitions(path, raw, name):
    module = types.ModuleType(name)
    module.__file__ = str(BASE / path)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def stage_program(helper, inputs):
    """Same fixed stage target and original 180s timer; no UI program."""
    source, wire = helper.make_source(inputs)
    literal = '(\n' + '\n'.join(' ' + repr(source[at:at + 256])
                               for at in range(0, len(source), 256)) + '\n)'
    program = ('import signal,sys\nsignal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(180)\n' +
        'namespace={"__name__":"fixed_sender_ui_v5_asset_stage"}\n' +
        'status=1\ntry:\n exec(compile(' + literal + ',"<fixed-sender-ui-v5-asset-stage>","exec"),namespace)\n' +
        'except SystemExit as error:\n status=error.code\n' +
        'component=namespace.get("component")\n' +
        'if type(component)is dict and component.get("original_fds_closed")is True and component.get("resource_pending")is False:signal.setitimer(signal.ITIMER_REAL,0.0)\n' +
        'raise SystemExit(status)\n')
    return program.encode('ascii'), wire


def component(raw, helper):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
    need(len(rows) == 1 and len(rows[0]) <= 16384 and
         derived.splitlines().count('MTA_REMOTE_OK') == 1, 'component_missing')
    value = ast.literal_eval(rows[0])
    need(type(value) is dict and set(value) == helper.FIELDS and
         all(type(value[key]) is bool for key in helper.BOOL_FIELDS) and
         all(type(value[key]) is int and 0 <= value[key] <= 8192 for key in helper.COUNT_FIELDS) and
         value['reason'] in helper.REASONS, 'component_fields')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-device', action='store_true',
                        help='exclusive new19 assets/readback only; never starts UI or RF')
    args = parser.parse_args()
    mode = 'stage' if args.stage_device else 'source'
    out = BASE / 'results' / ('formal-send-filecenter-ui-v5-assets-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    inputs = {}
    report = dict(mode=mode, passed=False, source_checked=False, source_preserved=False,
        device_invoked=False, runtime_requested=False, runtime_executed=False, execution_unknown=False,
        stage_requested=args.stage_device, ui_requested=False, qt_started=False,
        boot_started=False, owner_started=False, sender_worker_started=False, receiver_worker_started=False,
        credentials_created=False, credentials_read=False, rf_requested=False, automatic_actions=False,
        phone_tested=False, core_assets_staged_by_this_entry=False, other_ui_sessions_preserved=True,
        partial_assets_preserved=True, carrier_retained=True, physical_stdin_eof_verified=False,
        old_tests=0, old_builders=0, old_main_executed=False,
        stage_activity_seconds=60, stage_cleanup_seconds=60, remote_alarm_seconds=180,
        host_timeout_seconds=210, carrier_outer_seconds=810,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', component=None,
        stock_before_verified=False, stock_after_verified=False, error_kind=None)
    common = helper = carrier = transport = adb = before = created = launched = None
    try:
        for path, size, sha in (COMMON, ASSET_HELPER, CARRIER_HELPER, TRANSPORT, VALIDATOR):
            raw = (BASE / path).read_bytes()
            need((len(raw), digest(raw)) == (size, sha), 'source_pin')
            inputs[path] = raw
        common = definitions(COMMON[0], inputs[COMMON[0]], 'fixed_ui_v5_stage_carrier_definitions')
        helper = definitions(ASSET_HELPER[0], inputs[ASSET_HELPER[0]], 'fixed_ui_v5_assets_generator')
        carrier = definitions(CARRIER_HELPER[0], inputs[CARRIER_HELPER[0]], 'fixed_ui_v5_asset_carrier_definitions')
        validator = definitions(VALIDATOR[0], inputs[VALIDATOR[0]], 'fixed_ui_v5_asset_validator_definitions')
        need(common.SESSION == validator.SESSION == SESSION and common.REMOTE == validator.REMOTE == REMOTE and
             common.BUNDLE == BUNDLE and common.VALIDATOR == VALIDATOR and
             common.ASSET_HELPER == ASSET_HELPER and common.CARRIER_HELPER == CARRIER_HELPER and
             common.TRANSPORT == TRANSPORT, 'helper_identity')
        helper.SESSION, helper.BUNDLE, helper.REMOTE, helper.VALIDATOR = SESSION, BUNDLE, REMOTE, VALIDATOR
        helper.PINS = validator.PINS
        helper.MANIFEST = ('SOURCE.sha256',) + validator.MANIFEST_PIN
        helper.ASSET_PINS = helper.PINS + (helper.MANIFEST,)
        need(sum(row[1] for row in helper.ASSET_PINS) == ASSET_BYTES < 4 * 1024 * 1024, 'asset_budget')
        old_pin = "(12509,'63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5')"
        need(helper.TARGET.count('4182249') == 1 and helper.TARGET.count(old_pin) == 1, 'target_template')
        helper.TARGET = helper.TARGET.replace('4182249', str(ASSET_BYTES)).replace(old_pin, repr(VALIDATOR[1:]))
        need('4182249' not in helper.TARGET and old_pin not in helper.TARGET, 'old_target_identity')
        inputs[STAGE_MANIFEST[0]] = helper.read_fixed(STAGE_MANIFEST[0], STAGE_MANIFEST[1:])
        stage = json.loads(inputs[STAGE_MANIFEST[0]])
        need(stage['session'] == SESSION and stage['remote'] == REMOTE and
             tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files']) ==
             tuple(sorted(helper.ASSET_PINS)) and
             stage['directories'] == [dict(path=name, mode='0700') for name in ('', 'mta', 'toolbox')] and
             all(row['mode'] == ('0500' if row['path'] == 'Z03.mta-ui-candidate' else '0400') for row in stage['files']) and
             stage['credentials_in_stage'] is False and len(stage['files']) == 19, 'asset_manifest_pins')
        for name, size, sha in helper.ASSET_PINS:
            inputs[BUNDLE + '/' + name] = helper.read_fixed(BUNDLE + '/' + name, (size, sha))
        expected = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in helper.PINS).encode('ascii')
        need(inputs[BUNDLE + '/SOURCE.sha256'] == expected, 'source_manifest')
        for path in (SELF, CMD): inputs[path] = helper.read_fixed(path)
        program, wire = stage_program(helper, inputs)
        need(len(program) <= 2 * 1024 * 1024 and max(map(len, program.splitlines())) <= 2048 and
             len(wire) <= 6 * 1024 * 1024, 'program_budget')
        ast.parse(program, feature_version=(3, 5))
        body = common.carrier_body(carrier)
        carrier_sources = common.check_carrier_sources(body, {'stage': (program, wire)}, out)
        write_new(out / 'private-stage-bootstrap.py', program)
        write_new(out / 'private-stage-wire.raw', wire)
        for path, raw in inputs.items(): write_new(out / 'private-inputs' / path, raw)
        report.update(source_checked=True, carrier_sources_syntax_checked=True,
            carrier_metadata_fixture_is_authority=False, carrier_sources=carrier_sources,
            input_count=len(inputs), asset_bytes=ASSET_BYTES, asset_files=19, session=SESSION,
            program_bytes=len(program), program_sha256=digest(program),
            max_line_bytes=max(map(len, program.splitlines())), wire_bytes=len(wire), wire_sha256=digest(wire))
        if args.stage_device:
            transport = definitions(TRANSPORT[0], inputs[TRANSPORT[0]], 'fixed_ui_v5_assets_transport')
            need(Path(transport.ADB).resolve() == Path('C:/Program Files/ADB/adb.exe').resolve(), 'transport_identity')
            report['device_invoked'] = True
            adb = transport.Adb(private)
            before = adb.python('stock-before', transport.source(), timeout=45)
            write_new(private / 'stock-before.private.json', (json.dumps(before, sort_keys=True) + '\n').encode('ascii'))
            report['stock_before_verified'] = common.stock_identity(before, transport.PINS)
            need(report['stock_before_verified'], 'stock_before')
            pins = ((len(program), digest(program)), (len(wire), digest(wire)))
            # The pinned shared carrier intentionally retains its v4 prefix.
            leaf = 'p011-mta-ui-carrier-v4-' + secrets.token_hex(12)
            remote = '/var/volatile/tmp/' + leaf
            write_new(private / 'carrier-root.private', remote.encode('ascii'))
            rec, raw, error = common.run_carrier(adb, private, 'carrier-create',
                common.carrier_source(body, 'create', leaf, pins), 30)
            report['carrier_create'] = rec
            created = carrier.carrier_result(raw, 'create')
            write_new(private / 'carrier-create.private.json', (json.dumps(created) + '\n').encode('ascii'))
            need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                 created['carrier_created'] and created['resources_closed'], 'carrier_create')
            for name, data in (('bootstrap.py', program), ('wire.raw', wire)):
                local = private / 'carrier-inputs' / name
                write_new(local, data)
                label = 'push-' + name.split('.')[0]
                stem = '%02d-%s' % (adb.index + 1, label)
                try: adb.run(label, ['push', str(local), remote + '/' + name], timeout=45)
                finally:
                    rec, ignored = common.receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
                    report.setdefault('push_receipts', []).append(rec)
                need(rec['host_exit'] == 0, 'carrier_push')
            report['runtime_requested'] = report['execution_unknown'] = True
            rec, raw, error = common.run_carrier(adb, private, 'carrier-launch',
                common.carrier_source(body, 'launch', leaf, pins, created['root_metadata']), 210)
            report.update(host_exit=rec['host_exit'], remote_exit=rec['remote_exit'], carrier_launch=rec)
            launched = carrier.carrier_result(raw, 'launch')
            write_new(private / 'carrier-launch.private.json', (json.dumps(launched) + '\n').encode('ascii'))
            value = component(raw, helper)
            report.update(component=value, runtime_executed=True, execution_unknown=False)
            need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                 launched['resources_closed'] and launched['stdin_regular_verified'] and launched['stdin_closed'], 'carrier_launch')
            need(value['complete'] is True and value['reason'] == 'complete' and
                 value['resource_pending'] is False and value['staging_pending'] is False and
                 all(value[key] for key in helper.BOOL_FIELDS if key not in ('resource_pending', 'staging_pending')) and
                 value['created_file_count'] in (0, 19) and value['created_directory_count'] in (0, 3, 4) and
                 value['original_opened_fd_count'] == value['original_closed_fd_count'] > 0 and
                 value['validator_opened_fd_count'] == value['validator_closed_fd_count'] == 27 and
                 value['validator_files_verified'] == 19 and value['validator_readback_passes'] == 38, 'stage_refused')
    except BaseException as error:
        report['error_kind'] = type(error).__name__
        write_new(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            if created is not None:
                try:
                    rec, raw, error = common.run_carrier(adb, private, 'carrier-after',
                        common.carrier_source(body, 'inspect', leaf, pins, created['root_metadata'],
                            launched['files'] if launched is not None else None), 30)
                    report['carrier_after'] = rec
                    post = carrier.carrier_result(raw, 'inspect')
                    write_new(private / 'carrier-after.private.json', (json.dumps(post) + '\n').encode('ascii'))
                    need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                         post['resources_closed'] and post['files_stable'], 'carrier_after')
                    report['carrier_files_after_verified'] = True
                except BaseException:
                    report['carrier_files_after_verified'] = False
                    if report['error_kind'] is None: report['error_kind'] = 'CarrierAfterError'
                    write_new(private / 'carrier-after-error.private.txt', traceback.format_exc().encode('utf-8'))
            try:
                after = adb.python('stock-after', transport.source(), timeout=45)
                write_new(private / 'stock-after.private.json', (json.dumps(after, sort_keys=True) + '\n').encode('ascii'))
                report['stock_after_verified'] = common.stock_identity(after, transport.PINS)
                report['stock_files_unchanged'] = before is not None and before['stock']['hashes'] == after['stock']['hashes']
                need(report['stock_after_verified'] and report['stock_files_unchanged'], 'stock_after')
            except BaseException:
                if report['error_kind'] is None: report['error_kind'] = 'StockAfterError'
                write_new(private / 'stock-after-error.private.txt', traceback.format_exc().encode('utf-8'))
        try:
            report['source_preserved'] = bool(inputs) and all((BASE / path).read_bytes() == raw and
                (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items())
        except BaseException: report['source_preserved'] = False
    report['passed'] = report['source_checked'] and report['source_preserved'] and report['error_kind'] is None and (
        mode == 'source' or report.get('carrier_files_after_verified') is True and report['stock_after_verified'])
    encoded = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE only. --stage-device only stages/reads the new fixed19 UI assets.\n'
        b'Existing exact complete assets may pass readback; partial/conflicting assets remain untouched and refused.\n'
        b'Original target60+60/alarm180/host210 remain. Carrier launcher closes original FD>=3 before target.\n'
        b'No UI/Qt/Boot/Owner/sender/receiver/credentials/RF. No v4 core or other UI session changes.\n'
        b'Exclusive carrier and fixed SHA-framed wire; carrier metadata comes from actual create, not PC syntax fixtures.\n'
        b'Raw/exits/target/vendor assets remain local and private; public ZIP only metadata+README.\n'
        b'No old main/tests/builders or full runtime graph replay; SOURCE is not device/visual/phone acceptance.\n')
    write_new(out / 'result.json', encoded)
    write_new(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', encoded)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == encoded and archive.read('README.txt') == readme, 'public_zip')
    code = 0 if report['passed'] else 1
    write_new(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out), error_kind=report['error_kind'])))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
