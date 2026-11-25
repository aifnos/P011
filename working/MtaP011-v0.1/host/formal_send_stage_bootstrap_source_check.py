"""PC-only immutable bootstrap assembly. Never execute either target source."""
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_stage_bootstrap_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_STAGE_BOOTSTRAP_SOURCE_CHECK.cmd'
OLD = 'results/formal-send-stage-source-20261004-182447-21000000'
OLD_RESULT = (OLD + '/result.json', 1486,
              'd144004b911d039bd5cc11eb6ed0fb6583f3230fc185ff91a45864f0107c918e')
OLD_GENERATOR = ('host/formal_send_stage_source_check.py', 17979,
                 'db79f3f1b7ef7ac3dc1fb92865d4d2583a7539f7c5cd62be3a3537d55c52d45c')
OLD_CMD = ('HOST_MTA_FORMAL_SEND_STAGE_SOURCE_CHECK.cmd', 158,
           'f2349f6a3fa4d2bcc2f2f0b5a547ed71b1d4fc2a97cbef5a64fcf913f1f6ba3e')
STAGE = ('candidate/formal-send-stage-v1/runtime/formal_send_stage.py', 37382,
         'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806')
CATALOGS = (
    ('candidate/formal-send-v1/assets/ordinary-source-manifest.json', 18219,
     '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1'),
    ('candidate/formal-send-v1/assets/asset-sources.json', 23552,
     '27366f2510d07f2dd74eb65533c314f48d7b437bb574744c57203e28746a076a'),
    ('candidate/formal-send-v1/assets/sender-source-manifest.json', 3677,
     'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
)
DATA = ('candidate/formal-send-stage-bootstrap-v1/runtime/programs.py', 69849,
        'f2c1e165a4e4394365d30ffac9d7fc28d3ab03f4573cbbfba5ec98424ebf93c1')
WRAPPER = ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py', 13207,
           'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d')
PROGRAMS = (
    ('sender', 23954, 'c5171604bbc3e58ee73a317d3d6e76e7338d7140cbed610322aff7cfc87cd36f'),
    ('observer', 25816, 'a650fe89312d9a3cad60a8a7802f4d88218813183d7547b1721383af5589d953'),
    ('ordinary', 25230, 'a79ef9f3be2f50fb74e9e260a08cdb2f98d7a028aa2f485763baee28990c4bb7'),
)
WIRES = (
    ('sender', 1218562, '7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0'),
    ('observer', 475365, '569af62782d444ff2be330000d7f0f85ce1c5b30698e767ba6bef3d7797aabb7'),
    ('ordinary', 468929, '1a92780f8673a8dd52cc51a240e882a3208559eee518ea628e7f38235c53aaec'),
)
TOTALS = (('sender', 27, 2402458), ('observer', 41, 1440449), ('ordinary', 37, 1266713))
MAX_PROGRAM = 2097152
MAX_RAW = MAX_WIRE = 4194304
DATA_MODULE = 'formal_send_stage_bootstrap_programs'
DATA_FILE = '<formal-send-stage-bootstrap-programs-v1>'
ERROR_CODES = frozenset(('fixed_path', 'fixed_file', 'fixed_changed', 'fixed_pin',
    'old_inventory', 'old_snapshot', 'old_result', 'source_table', 'source_contract',
    'source_budget', 'source_preserved', 'wire_copy', 'result_readback', 'zip_readback'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = ROOT
    for ancestor in reversed((ROOT,) + tuple(ROOT.parents)):
        value = ancestor.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('fixed_path')
    for index, part in enumerate(name.split('/')):
        path = path / part
        value = path.lstat()
        if (stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400 or
                index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode)):
            raise ValueError('fixed_path')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= MAX_WIRE:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not same:
            raise ValueError('fixed_changed')
        raw = handle.read(MAX_WIRE + 1)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('fixed_changed')
    if len(raw) != before[4] or metadata(path.lstat()) != before:
        raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin:
        raise ValueError('fixed_pin')
    return raw


def original_inventory(inputs):
    ordinary = json.loads(inputs[CATALOGS[0][0]])
    assets = json.loads(inputs[CATALOGS[1][0]])
    sender = json.loads(inputs[CATALOGS[2][0]])
    if (ordinary['schema'] != 'p011-formal-send-v1-ordinary-source-catalog' or
            ordinary['source_count'] != 32 or len(ordinary['sources']) != 32 or
            len(ordinary['startup_sources']) != 3 or len(ordinary['helper_sources']) != 3 or
            assets['sender_source_count'] != 25 or len(assets['sender_sources']) != 25 or
            assets['observer_source_count'] != 41 or len(assets['observer_sources']) != 41 or
            sender['schema'] != 'p011-go-send-assets-v76' or
            sender['sources'] != [[row['module'], row['bytes'], row['sha256']] for row in assets['sender_sources']]):
        raise ValueError('old_inventory')
    pins = {path: (size, sha) for path, size, sha in CATALOGS + (STAGE, OLD_GENERATOR, OLD_CMD)}
    all_rows = (ordinary['sources'] + ordinary['startup_sources'] + ordinary['helper_sources'] +
                assets['sender_sources'] + assets['observer_sources'] + [assets['sender_manifest'], assets['wpa']])
    for row in all_rows:
        pin = (row['bytes'], row['sha256'])
        if row['source'] in pins and pins[row['source']] != pin:
            raise ValueError('old_inventory')
        pins[row['source']] = pin
    if len(pins) != 90:
        raise ValueError('old_inventory')
    return pins


def snapshot_paths():
    root = ROOT / OLD / 'private-inputs'
    paths = set()
    for item in root.rglob('*'):
        value = item.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('old_snapshot')
        if stat.S_ISREG(value.st_mode):
            paths.add(item.relative_to(root).as_posix())
        elif not stat.S_ISDIR(value.st_mode):
            raise ValueError('old_snapshot')
    return paths


def literal(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(rows) != 1:
        raise ValueError('source_contract')
    return ast.literal_eval(rows[0])


def source_contract(data_raw, wrapper_raw, inputs):
    data = ast.parse(data_raw.decode('ascii'), feature_version=(3, 5))
    wrapper = ast.parse(wrapper_raw.decode('ascii'), feature_version=(3, 5))
    rows = literal(data, 'PROGRAM_ROWS')
    if (type(rows) is not tuple or len(rows) != 3 or tuple(row[:3] for row in rows) != PROGRAMS or
            any(type(row) is not tuple or len(row) != 4 or type(row[3]) is not str for row in rows) or
            any(not isinstance(node, (ast.Assign, ast.Expr)) for node in data.body)):
        raise ValueError('source_table')
    for row in rows:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(base64.b64decode(row[3], validate=True), row[1] + 1)
        if (len(raw) != row[1] or digest(raw) != row[2] or not decoder.eof or decoder.unused_data or
                decoder.unconsumed_tail or raw != inputs[OLD + '/' + row[0] + '.program.py']):
            raise ValueError('source_table')
    expected = {'DATA_PIN': DATA[1:], 'STAGE_PIN': STAGE[1:], 'PROGRAM_PINS': PROGRAMS,
                'WIRE_PINS': WIRES, 'MAX_PROGRAM': MAX_PROGRAM, 'MAX_WIRE': MAX_WIRE,
                'MAX_RAW': MAX_RAW, 'OUTER_SECONDS': 180.0, 'INNER_SECONDS': 120.0,
                'DATA_MODULE': DATA_MODULE, 'DATA_FILE': DATA_FILE}
    if any(literal(wrapper, name) != value for name, value in expected.items()):
        raise ValueError('source_contract')
    functions = [node for node in wrapper.body if isinstance(node, ast.FunctionDef) and node.name == 'run_fixed']
    if (len(functions) != 1 or tuple(arg.arg for arg in functions[0].args.args) != ('profile',) or
            functions[0].args.defaults or functions[0].args.vararg or functions[0].args.kwarg):
        raise ValueError('source_contract')
    # There is no top-level run_fixed call, reader, transport or graph execution.
    for node in wrapper.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            raise ValueError('source_contract')
    if any(len(line) > 256 for line in data_raw.splitlines() + wrapper_raw.splitlines()):
        raise ValueError('source_budget')
    return data, wrapper


def chunks(raw):
    encoded = base64.b64encode(zlib.compress(raw)).decode('ascii')
    return '\n'.join('    ' + repr(encoded[index:index + 96]) for index in range(0, len(encoded), 96))


ENVELOPE = r'''
import base64,hashlib,sys,types,zlib
_ORIGINALS=[]
def fixed_decode(encoded,pin):
 decoder=zlib.decompressobj()
 raw=decoder.decompress(base64.b64decode(encoded,validate=True),pin[0]+1)
 if not (len(raw)==pin[0]<=2097152 and decoder.eof and not decoder.unused_data and
  not decoder.unconsumed_tail and hashlib.sha256(raw).hexdigest()==pin[1]):raise ValueError('bootstrap_source_pin')
 return raw
_data_raw=fixed_decode(DATA_B64,DATA_PIN)
_wrapper_raw=fixed_decode(WRAPPER_B64,WRAPPER_PIN)
if DATA_MODULE in sys.modules:raise ValueError('bootstrap_module_present')
_data=types.ModuleType(DATA_MODULE)
_data.__file__='<formal-send-stage-bootstrap-programs-v1>'
_data._fixed_source_raw=_data_raw
_ORIGINALS.append((_data,_data.__dict__,_data_raw))
sys.modules[DATA_MODULE]=_data
exec(compile(_data_raw,_data.__file__,'exec'),_data.__dict__)
_wrapper=types.ModuleType('formal_send_stage_bootstrap_private')
_wrapper.__file__='<formal-send-stage-bootstrap-v1>'
_ORIGINALS.append((_wrapper,_wrapper.__dict__,_wrapper_raw))
exec(compile(_wrapper_raw,_wrapper.__file__,'exec'),_wrapper.__dict__)
_wrapper.run_fixed(PROFILE)
'''


def make_program(profile, data_raw, wrapper_raw):
    if profile not in ('sender', 'observer', 'ordinary'):
        raise ValueError('source_contract')
    lines = ['PROFILE=' + repr(profile), 'DATA_MODULE=' + repr(DATA_MODULE),
             'DATA_PIN=' + repr(DATA[1:]), 'WRAPPER_PIN=' + repr(WRAPPER[1:]),
             'DATA_B64=(', chunks(data_raw), ')', 'WRAPPER_B64=(', chunks(wrapper_raw), ')']
    raw = ('\n'.join(lines) + '\n' + ENVELOPE).encode('ascii')
    if len(raw) > MAX_PROGRAM or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('source_budget')
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    if (literal(tree, 'PROFILE') != profile or literal(tree, 'DATA_MODULE') != DATA_MODULE or
            literal(tree, 'DATA_PIN') != DATA[1:] or literal(tree, 'WRAPPER_PIN') != WRAPPER[1:]):
        raise ValueError('source_contract')
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
             isinstance(node.func, ast.Attribute) and node.func.attr == 'run_fixed']
    if (len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords or
            not isinstance(calls[0].args[0], ast.Name) or calls[0].args[0].id != 'PROFILE'):
        raise ValueError('source_contract')
    return raw


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def finite_error(error):
    if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERROR_CODES):
        return error.args[0]
    return {OSError: 'host_io', SyntaxError: 'host_syntax', ValueError: 'host_value',
            TypeError: 'host_type', KeyError: 'host_key'}.get(type(error), 'host_unknown')


def main():
    if len(sys.argv) != 1:
        print('PC SOURCE only; no device/profile/argument executor')
        return 2
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = ROOT / 'results' / ('formal-send-stage-bootstrap-source-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    inputs, outputs, old_pins = {}, {}, None
    report = dict(kind='formal-send-stage-bootstrap-v1-source', passed=False, error_code=None,
        source_complete=False, source_preserved=False, source_inputs=0, original_source_inputs=90,
        original_inputs_reused=False, original_programs_reused=False, original_wires_reused=False,
        decoded_limit=MAX_RAW, wire_limit=MAX_WIRE, program_limit=MAX_PROGRAM, line_limit=256,
        outer_seconds=180, inner_seconds=120, old_program_ast_count=0, old_stager_ast_count=0,
        new_runtime_ast_count=0, new_envelope_ast_count=0, wrapper_executed=False,
        target_program_executed=False, stage_executed=False, device=False, business_graph_executed=False,
        actual_timer_tested=False, physical_stdin_eof_verified=False, batches=[])
    try:
        for pin in CATALOGS + (STAGE, OLD_GENERATOR, OLD_CMD, OLD_RESULT, DATA, WRAPPER):
            inputs[pin[0]] = read_fixed(pin[0], pin[1:])
        old_pins = original_inventory(inputs)
        if snapshot_paths() != set(old_pins):
            raise ValueError('old_snapshot')
        for path, pin in old_pins.items():
            raw = read_fixed(path, pin)
            if raw != read_fixed(OLD + '/private-inputs/' + path, pin):
                raise ValueError('old_snapshot')
            inputs[path] = raw
        result = json.loads(inputs[OLD_RESULT[0]])
        expected_batches = [dict(profile=p[0], files=t[1], decoded_bytes=t[2], program_bytes=p[1],
            program_sha256=p[2], wire_bytes=w[1], wire_sha256=w[2]) for p,w,t in zip(PROGRAMS,WIRES,TOTALS)]
        if (result.get('passed') is not True or result.get('source_preserved') is not True or
                result.get('source_inputs') != 90 or result.get('batches') != expected_batches or
                any(result.get(key) is not False for key in
                    ('device', 'stage_executed', 'boot', 'owner', 'helper', 'receive', 'send', 'rf', 'restoration', 'phone'))):
            raise ValueError('old_result')
        for p,w,t in zip(PROGRAMS,WIRES,TOTALS):
            program_path, wire_path = OLD + '/' + p[0] + '.program.py', OLD + '/' + p[0] + '.wire.raw'
            inputs[program_path] = read_fixed(program_path, p[1:])
            inputs[wire_path] = read_fixed(wire_path, w[1:])
            if (p[1] > MAX_PROGRAM or w[1] > MAX_WIRE or t[2] > MAX_RAW or
                    any(len(line) > 256 for line in inputs[program_path].splitlines()) or
                    any(len(line) > 256 for line in inputs[wire_path].splitlines())):
                raise ValueError('source_budget')
        inputs[SELF], inputs[CMD] = read_fixed(SELF), read_fixed(CMD)
        source_contract(inputs[DATA[0]], inputs[WRAPPER[0]], inputs)
        report.update(original_inputs_reused=True, original_programs_reused=True,
                      original_wires_reused=True, new_runtime_ast_count=2)
        for p,w,t in zip(PROGRAMS,WIRES,TOTALS):
            raw = make_program(p[0], inputs[DATA[0]], inputs[WRAPPER[0]])
            outputs[p[0] + '.bootstrap.py'] = raw
            outputs[p[0] + '.wire.raw'] = inputs[OLD + '/' + p[0] + '.wire.raw']
            report['batches'].append(dict(profile=p[0], bootstrap_bytes=len(raw), bootstrap_sha256=digest(raw),
                original_program_bytes=p[1], original_program_sha256=p[2], wire_bytes=w[1], wire_sha256=w[2],
                decoded_bytes=t[2], fixed_files=t[1], physical_line_max=max(map(len, raw.splitlines()))))
        if len(inputs) != 101:
            raise ValueError('old_inventory')
        for name, raw in outputs.items():
            write_new(out / name, raw)
        report.update(source_complete=True, new_envelope_ast_count=3)
    except BaseException as source_error:
        report['error_code'] = finite_error(source_error)
    finally:
        preserved = bool(inputs) and old_pins is not None and len(outputs) == 6
        for path, raw in inputs.items():
            try:
                target = out / 'private-inputs' / path
                target.parent.mkdir(parents=True, exist_ok=True)
                write_new(target, raw)
                if target.read_bytes() != raw or read_fixed(path) != raw:
                    preserved = False
            except BaseException:
                preserved = False
        if old_pins is not None:
            try:
                if snapshot_paths() != set(old_pins):
                    preserved = False
                for path in old_pins:
                    if read_fixed(OLD + '/private-inputs/' + path) != inputs[path]:
                        preserved = False
            except BaseException:
                preserved = False
        for name, raw in outputs.items():
            try:
                if (out / name).read_bytes() != raw:
                    preserved = False
            except BaseException:
                preserved = False
        report['source_inputs'], report['source_preserved'] = len(inputs), preserved
    report['passed'] = report['source_complete'] and report['source_preserved'] and report['error_code'] is None
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'PC SOURCE assembly only; no wrapper, original program, stage, business graph or device runs.\n'
        b'The exact original90 inputs and three passed programs/wires are readback reused, not regenerated.\n'
        b'Only three trusted profiles have fixed bootstrap programs; source is in fixed data, never read from stdin.\n'
        b'Standard input remains original wire. Its fixed trailer is not physical EOF or absence of trailing bytes.\n'
        b'One original outer180 period covers unchanged inner120; existing SIGALRM/timer are not adopted.\n'
        b'Unknown original IO/timer inventory remains pending. Original STAGE_RESULT/errors/exit are retained.\n'
        b'Decoded4MiB/wire4MiB/program2MiB/line256 caps stay unchanged. No extra execution authority is supplied.\n'
        b'Target source, program data, raw wire and source snapshots are private; ZIP has only this result and README.\n'
        b'SOURCE success does not prove timers, POSIX stage IO, device publication, sending or restoration.\n')
    write_new(out / 'result.json', public)
    write_new(out / 'README.txt', readme)
    archive = out / 'SOURCE_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as handle:
        handle.writestr('result.json', public)
        handle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as handle:
        if (handle.namelist() != ['result.json', 'README.txt'] or handle.testzip() is not None or
                handle.read('result.json') != public or handle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    if (out / 'result.json').read_bytes() != public or (out / 'README.txt').read_bytes() != readme:
        raise ValueError('result_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
