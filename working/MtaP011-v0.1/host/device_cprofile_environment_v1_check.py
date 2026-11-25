"""Default PC SOURCE; explicit --device inventories _lsprof/cProfile only.

Native Profiler and wrapper Profile are constructed independently, never run.
Missing dependencies complete the query; they do not certify profiling usable.
No installation, staging, runtime candidate, RF, UI, phone or timing action.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_cprofile_environment_v1_check.py'
CMDS = ('HOST_MTA_CPROFILE_ENVIRONMENT_V1_CHECK.cmd', 'TEST_MTA_CPROFILE_ENVIRONMENT_V1.cmd')
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/device_filecenter_audio_deadline_v1_check.py', 13753,
     '69f7c6d4b192f1ab7a7c75101a6583d31773141e007b7f33c5ba2e457763d71c'))
MODULES = ('_lsprof', 'cProfile')
CONSTRUCTORS = ('Profiler', 'Profile')
ATTRIBUTES = ('getstats', 'enable', 'disable')

REMOTE = r'''
import os,sys
if os.geteuid()!=0 or os.uname()[4]!='armv7l':raise ValueError('target_profile')
if tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_python')
rows=[];loaded={}
for name in MODULES:
 try:
  loaded[name]=__import__(name,fromlist=['*'])
  rows.append((name,True,None))
 except Exception as error:rows.append((name,False,type(error).__name__))
profiles=[]
for name,constructor in zip(MODULES,CONSTRUCTORS):
 profile=None;profile_error=None
 if loaded.get(name) is not None:
  try:profile=getattr(loaded[name],constructor)()
  except Exception as error:profile_error=type(error).__name__
 flags=tuple(callable(getattr(profile,attribute,None)) for attribute in ATTRIBUTES)
 profiles.append((name,profile is not None,profile_error)+flags)
result=dict(schema='p011-cprofile-environment-v1',python_version=tuple(sys.version_info[:3]),
 modules=tuple(rows),profiles=tuple(profiles),
 profiling_enabled=False,profiling_ran=False,profile_stats_read=False)
print('CPROFILE_ENVIRONMENT='+repr(result))
'''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def definition(key, raw):
    value = types.ModuleType('_cprofile_environment_' + Path(key).stem)
    value.__file__ = str(BASE / key)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def error_category(value):
    return (type(value) is str and 1 <= len(value) <= 64 and value.isascii() and
            value.isidentifier())


def validate(value):
    fields = {'schema', 'python_version', 'modules', 'profiles',
              'profiling_enabled', 'profiling_ran', 'profile_stats_read'}
    need(type(value) is dict and set(value) == fields and
         value['schema'] == 'p011-cprofile-environment-v1' and
         type(value['python_version']) is tuple and value['python_version'] == (3, 5, 5) and
         all(type(item) is int for item in value['python_version']), 'observation_schema')
    rows = value['modules']
    need(type(rows) is tuple and len(rows) == 2 and
         all(type(row) is tuple and len(row) == 3 for row in rows), 'module_rows')
    need(tuple(row[0] for row in rows) == MODULES and
         all(type(row[1]) is bool and
             (row[2] is None if row[1] else error_category(row[2])) for row in rows),
         'module_observations')
    profiles = value['profiles']
    need(type(profiles) is tuple and len(profiles) == 2 and
         all(type(row) is tuple and len(row) == 6 for row in profiles) and
         tuple(row[0] for row in profiles) == MODULES and
         all(type(row[index]) is bool for row in profiles for index in (1, 3, 4, 5)),
         'independent_profile_observations')
    for module, profile in zip(rows, profiles):
        constructed, error = profile[1:3]
        need(error is None or error_category(error), 'constructor_error_category')
        need((constructed and module[1] is True and error is None) or
             (not constructed and not any(profile[3:]) and
              (error_category(error) if module[1] else error is None)), 'constructor_consistency')
    need(all(value[name] is False for name in ('profiling_enabled', 'profiling_ran', 'profile_stats_read')),
         'profiling_not_invoked')
    return dict(schema=value['schema'], python_version=value['python_version'], modules=rows,
        profiles=profiles, profile_constructor_order=CONSTRUCTORS, profile_callable_order=ATTRIBUTES,
        dependency_query_complete=True,
        native_dependency_contract_present=rows[0][1] and profiles[0][1] and all(profiles[0][3:]),
        wrapper_dependency_contract_present=rows[1][1] and profiles[1][1] and all(profiles[1][3:]),
        actual_profiling_verified=False, profiling_enabled=False, profiling_ran=False, profile_stats_read=False)


def run(device):
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == PINS[0][1:], 'sealer_pin')
    seal = definition(PINS[0][0], raw)
    mode = 'device' if device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('cprofile-environment-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}; evidence = seal.InputEvidence(inputs)
    report = dict(schema='p011-cprofile-environment-v1-parent', mode=mode, passed=False,
        device_attempted=False, dependency_attempted=False, observation=None,
        source_preserved=False, stock_before_ok=False, stock_after_ok=False,
        limited_stock_unchanged=False, wifi_state_unchanged=False,
        device_writes=False, sockets_started=False, rf=False, ui=False, phone=False,
        installation_performed=False, staging_performed=False, runtime_candidate_invoked=False,
        profiling_invoked=False, timing_performed=False, actual_profiling_verified=False,
        startup_verified=False, full_restore_verified=False, error=None, command_receipts={})
    adb = probe = helper = before = baseline_command = None; failure = None
    try:
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF,) + CMDS:
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        probe = definition(PINS[1][0], inputs[PINS[1][0]])
        helper = definition(PINS[2][0], inputs[PINS[2][0]])
        target = ('MODULES=' + repr(MODULES) + '\nCONSTRUCTORS=' + repr(CONSTRUCTORS) +
                  '\nATTRIBUTES=' + repr(ATTRIBUTES) + '\n' + REMOTE).encode('ascii')
        ast.parse(target.decode('ascii'), feature_version=(3, 5))
        need(len(target) <= 4096 and max(map(len, target.splitlines())) <= 256, 'target_budget')
        seal.fresh(out / 'private-raw/target.py', target)
        packed = base64.b64encode(zlib.compress(probe.source().encode('utf-8'))).decode('ascii')
        baseline_command = ('/usr/bin/python3.5 -I -B -c "import signal,base64,zlib;signal.alarm(60);'
            'exec(zlib.decompress(base64.b64decode(\'' + packed + '\')))"; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(25);'
            'exec(sys.stdin.buffer.read(' + str(len(target)) + '))" p011-cprofile-environment-v1; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        need(len(baseline_command) <= 3500, 'baseline_command_limit')
        seal.fresh(out / 'private-raw/commands.txt', (baseline_command + '\n' + command + '\n').encode('ascii'))
        report.update(input_count=len(inputs), target_bytes=len(target),
            target_sha256=hashlib.sha256(target).hexdigest(), target_alarm_seconds=25,
            target_host_timeout_seconds=35, baseline_alarm_seconds=60,
            baseline_host_timeout_seconds=70, alarm_before_stdin=True)
        if device:
            adb = probe.Adb(out / 'private-raw'); report['device_attempted'] = True
            before = helper.stock_probe(adb, probe, 'stock-before', baseline_command, report['command_receipts'])
            report['stock_before_ok'] = True; report['dependency_attempted'] = True
            value = helper.reply(adb, 'cprofile-dependencies', command, 'CPROFILE_ENVIRONMENT=', 35,
                                 report['command_receipts'], target)
            report['observation'] = validate(value)
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            try:
                after = helper.stock_probe(adb, probe, 'stock-after', baseline_command, report['command_receipts'])
                report['stock_after_ok'] = True
                if before is not None:
                    report['limited_stock_unchanged'] = before['stock'] == after['stock']
                    report['wifi_state_unchanged'] = before['capabilities']['wifi_connected'] is after['capabilities']['wifi_connected']
                    need(report['limited_stock_unchanged'] and report['wifi_state_unchanged'], 'baseline_changed')
            except BaseException as error:
                seal.fresh(out / 'private-raw/after-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None: failure = error
        try:
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected, 'source_changed')
                need((out / 'private-inputs' / key).read_bytes() == expected, 'snapshot_changed')
            report['source_preserved'] = True
        except BaseException as error:
            seal.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        if failure is None: report['passed'] = True
        else: report['error'] = type(failure).__name__
    readme = (b'P011 readonly _lsprof/cProfile dependency query; SOURCE does not contact the device.\n'
        b'Independent _lsprof.Profiler/cProfile.Profile construction and callability only; no enable/run/disable/getstats/timing.\n'
        b'cProfile wrapper absence does not assert the native _lsprof Profiler is absent.\n'
        b'Missing modules are completed observations, not a failure to query or a profiling-usability PASS.\n'
        b'No installation, staging, runtime candidate, sockets, RF, UI, phone or system writes.\n'
        b'Stock/Wi-Fi comparison is limited; actual profiling, Startup and full restoration remain unverified.\n'
        b'Raw streams, remote exits, exceptions, source and input snapshots stay private.\n')
    sealed = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        error=sealed['report']['error'], result_dir=str(out), result_zip=str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', action='store_true')
    sys_exit = run(parser.parse_args().device)
    raise SystemExit(sys_exit)
