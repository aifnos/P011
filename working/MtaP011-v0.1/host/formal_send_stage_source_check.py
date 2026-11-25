#!/usr/bin/env python3
"""PC-only fixed three-batch source generator. No import/execute/ADB/device path."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import re
import sys
import time
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ('candidate/formal-send-stage-v1/runtime/formal_send_stage.py',
         37382, 'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806')
CATALOGS = (
    ('candidate/formal-send-v1/assets/ordinary-source-manifest.json',
     18219, '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1'),
    ('candidate/formal-send-v1/assets/asset-sources.json',
     23552, '27366f2510d07f2dd74eb65533c314f48d7b437bb574744c57203e28746a076a'),
    ('candidate/formal-send-v1/assets/sender-source-manifest.json',
     3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
)
SELF = 'host/formal_send_stage_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_STAGE_SOURCE_CHECK.cmd'
TOTALS = (('sender', 27, 2402458), ('observer', 41, 1440449), ('ordinary', 37, 1266713))
MAX_PROGRAM = 2 * 1024 * 1024
MAX_RAW = MAX_WIRE = 4 * 1024 * 1024
LINE = 96
ERROR_CODES = frozenset(('source_path', 'source_pin', 'source_literal', 'catalog_shape',
    'sender_manifest', 'batch_shape', 'target_shape', 'target_mode', 'source_changed',
    'shared_deployment', 'envelope_budget', 'fixed_profile_mapping', 'fixed_stage_budget'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(path, size=None, sha=None):
    if type(path) is not str or path.startswith(('/', '\\')) or '..' in path.split('/'):
        raise ValueError('source_path')
    file = ROOT / path
    before = file.stat()
    raw = file.read_bytes()
    after = file.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (tuple(getattr(before, key) for key in fields) != tuple(getattr(after, key) for key in fields) or
            size is not None and len(raw) != size or sha is not None and digest(raw) != sha):
        raise ValueError('source_pin')
    return raw


def literal(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(rows) != 1:
        raise ValueError('source_literal')
    node = rows[0]
    if name == 'RAW_LIMIT':
        # The pinned SOURCE uses this exact arithmetic expression, not a literal.
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult) and
                isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Mult) and
                all(isinstance(value, ast.Constant) and type(value.value) is int for value in
                    (node.left.left, node.left.right, node.right))):
            raise ValueError('fixed_stage_budget')
        factors = (node.left.left.value, node.left.right.value, node.right.value)
        if factors != (4, 1024, 1024):
            raise ValueError('fixed_stage_budget')
        return factors[0] * factors[1] * factors[2]
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        raise ValueError('source_literal') from None


def error_code(error):
    return error.args[0] if (type(error) is ValueError and len(error.args) == 1 and
        type(error.args[0]) is str and error.args[0] in ERROR_CODES) else 'unknown'


def catalogs(inputs):
    ordinary = json.loads(inputs[CATALOGS[0][0]])
    assets = json.loads(inputs[CATALOGS[1][0]])
    manifest = json.loads(inputs[CATALOGS[2][0]])
    if (ordinary['schema'] != 'p011-formal-send-v1-ordinary-source-catalog' or
            ordinary['source_count'] != 32 or len(ordinary['sources']) != 32 or
            len(ordinary['startup_sources']) != 3 or len(ordinary['helper_sources']) != 3 or
            ordinary['program_cap_bytes'] != MAX_PROGRAM or ordinary['wire_cap_bytes'] != MAX_WIRE or
            assets['sender_source_count'] != 25 or len(assets['sender_sources']) != 25 or
            assets['observer_source_count'] != 41 or len(assets['observer_sources']) != 41 or
            manifest['schema'] != 'p011-go-send-assets-v76' or len(manifest['sources']) != 25):
        raise ValueError('catalog_shape')
    if manifest['sources'] != [[row['module'], row['bytes'], row['sha256']] for row in assets['sender_sources']]:
        raise ValueError('sender_manifest')
    groups = (
        ('sender', assets['sender_root'],
         assets['sender_sources'] + [assets['sender_manifest'], assets['wpa']]),
        ('observer', assets['observer_root'], assets['observer_sources']),
        ('ordinary', '/var/volatile/tmp/p011-mta-formal-send-v1',
         [row for row in ordinary['sources'] if not row['reused_sender_asset']] +
         ordinary['startup_sources'] + ordinary['helper_sources']),
    )
    mapped = []
    files = []
    targets = set()
    for group, total in zip(groups, TOTALS):
        profile, root, rows = group
        pins = []
        current = []
        if profile != total[0] or len(rows) != total[1] or sum(row['bytes'] for row in rows) != total[2]:
            raise ValueError('batch_shape')
        for row in rows:
            target = row.get('physical_target', row['target'])
            if not target.startswith(root + '/') or target in targets:
                raise ValueError('target_shape')
            relative = target[len(root) + 1:]
            parts = relative.split('/')
            if len(parts) not in (1, 2) or any(re.fullmatch('[A-Za-z0-9_.-]{1,80}', part) is None for part in parts):
                raise ValueError('target_shape')
            mode = row.get('mode', '0400')
            if type(mode) is str:
                mode = int(mode, 8)
            if type(mode) is not int or mode not in (0o400, 0o500, 0o700):
                raise ValueError('target_mode')
            pin = (relative, row['bytes'], row['sha256'], mode)
            raw = read_fixed(row['source'], pin[1], pin[2])
            if row['source'] in inputs and inputs[row['source']] != raw:
                raise ValueError('source_changed')
            inputs[row['source']] = raw
            targets.add(target)
            pins.append(pin)
            current.append((pin, raw))
        mapped.append((profile, root, tuple(pins)))
        files.append(tuple(current))
    reused = [row for row in ordinary['sources'] if row['reused_sender_asset']]
    sender = [row for row in assets['sender_sources'] if row['module'] == 'mta_go_deployment']
    if (len(reused) != 1 or len(sender) != 1 or reused[0]['module'] != 'mta_go_deployment' or
            reused[0]['target'] != sender[0]['target'] or reused[0]['physical_target'] != sender[0]['target'] or
            (reused[0]['source'], reused[0]['bytes'], reused[0]['sha256']) !=
            (sender[0]['source'], sender[0]['bytes'], sender[0]['sha256']) or len(targets) != 105):
        raise ValueError('shared_deployment')
    return tuple(mapped), tuple(files)


def encoded_chunks(raw):
    encoded = base64.b64encode(zlib.compress(raw)).decode('ascii')
    return '\n'.join('    ' + repr(encoded[offset:offset + LINE]) for offset in range(0, len(encoded), LINE))


def frame(raw):
    encoded = base64.b64encode(zlib.compress(raw))
    return b''.join(encoded[offset:offset + LINE] + b'\n' for offset in range(0, len(encoded), LINE))


PROGRAM_BODY = r'''
import base64,hashlib,math,re,signal,sys,time,types,zlib
_RETAINED = None
_primary = None
_constructor_complete = False
_module = None
_result = None
_payload_framed_end_verified = False
values = []
_started = time.monotonic()
_until = _started + 120.0
_original_handler = signal.getsignal(signal.SIGALRM)
_original_timer = signal.getitimer(signal.ITIMER_REAL)
_outer_until = _started + _original_timer[0]


def require(value, code):
    if not value:
        raise ValueError(code)


def deadline(signum, frame):
    raise ValueError('deadline')


def current():
    value = time.monotonic()
    require(math.isfinite(value) and _started <= value < _until, 'deadline')
    return value


def read_exact(count):
    require(type(count) is int and 0 < count <= MAX_WIRE, 'frame')
    parts = []
    have = 0
    while have < count:
        remaining = _until - current()
        signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        try:
            raw = sys.stdin.buffer.read(min(65536, count - have))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, _original_handler)
            outer_remaining = _outer_until - time.monotonic()
            require(math.isfinite(outer_remaining) and outer_remaining > 0, 'deadline')
            signal.setitimer(signal.ITIMER_REAL, outer_remaining)
        current()
        require(type(raw) is bytes and 0 < len(raw) <= count - have, 'frame')
        parts.append(raw)
        have += len(raw)
    return b''.join(parts)


def decode(encoded, size, sha):
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(encoded, validate=True), size + 1)
    require(len(raw) == size and decoder.eof and not decoder.unused_data and
            not decoder.unconsumed_tail and hashlib.sha256(raw).hexdigest() == sha, 'pin')
    return raw


try:
    require(_original_handler == signal.SIG_DFL and _original_timer[1] == 0.0 and
            _outer_until >= _until, 'outer_deadline')
    source = decode(STAGE_B64.encode('ascii'), STAGE_PIN[0], STAGE_PIN[1])
    _module = types.ModuleType('formal_send_stage_private')
    _module.__file__ = '<fixed-stdin-stage>'
    exec(source, _module.__dict__)
    expected = [row for row in _module.PROFILE_FILES if row[0] == PROFILE]
    require(len(expected) == 1 and tuple(row[:4] for row in FRAME_ROWS) == expected[0][2], 'profile')
    require(sum(row[1] for row in FRAME_ROWS) == DECODED_BYTES <= MAX_RAW, 'raw_budget')
    require(sum(row[4] for row in FRAME_ROWS) + len(TRAILER) == WIRE_PIN[0] <= MAX_WIRE, 'wire_budget')
    _RETAINED = object.__new__(_module.FixedStage)
    _module.FixedStage.__init__(_RETAINED, PROFILE, _until)
    _constructor_complete = True
    wire_hash = hashlib.sha256()
    for row in FRAME_ROWS:
        encoded = read_exact(row[4])
        wire_hash.update(encoded)
        require(re.fullmatch(b'[A-Za-z0-9+/=\n]+', encoded) is not None and encoded.endswith(b'\n'), 'frame')
        lines = encoded.split(b'\n')
        require(lines[-1] == b'' and 0 < len(lines[-2]) <= 96 and
                all(len(line) == 96 for line in lines[:-2]), 'frame')
        raw = decode(encoded.replace(b'\n', b''), row[1], row[2])
        values.append((row[0], raw))
    require(TRAILER == b'MTA_FORMAL_SEND_STAGE_V1_END ' + PROFILE.encode('ascii') +
            b' ' + wire_hash.hexdigest().encode('ascii') + b'\n', 'trailer')
    trailer = read_exact(len(TRAILER))
    wire_hash.update(trailer)
    require(trailer == TRAILER and wire_hash.hexdigest() == WIRE_PIN[1], 'wire')
    _payload_framed_end_verified = True
    # Fixed framed end, not physical stdin EOF or absence of trailing input.
    _module.FixedStage.stage(_RETAINED, tuple(values))
except BaseException as error:
    _primary = error
finally:
    if _constructor_complete:
        try:
            if not _RETAINED.close_called:
                _module.FixedStage.close(_RETAINED)
        except BaseException as error:
            if _primary is None:
                _primary = error
        _result = _module.FixedStage.result(_RETAINED)
    else:
        _result = dict(stage_complete=False, resource_pending=True,
                       receive=False, send=False, boot=False, owner=False, helper=False,
                       rf=False, restoration=False, phone=False)
    _result['payload_framed_end_verified'] = _payload_framed_end_verified
    _result['physical_stdin_eof_verified'] = False
    _result['source_only_template'] = False
    print('STAGE_RESULT=' + repr(_result))
    if _primary is not None:
        print('STAGE_ERROR=' + type(_primary).__name__)
    if _primary is not None or _result.get('stage_complete') is not True:
        raise SystemExit(1)
    print('STAGE_OK=1')
'''


def make_program(profile, rows, stage):
    frames = tuple(frame(raw) for pin, raw in rows)
    data = b''.join(frames)
    trailer = b'MTA_FORMAL_SEND_STAGE_V1_END ' + profile.encode('ascii') + b' ' + digest(data).encode('ascii') + b'\n'
    wire = data + trailer
    lines = ['PROFILE=' + repr(profile), 'MAX_RAW=' + repr(MAX_RAW), 'MAX_WIRE=' + repr(MAX_WIRE),
             'DECODED_BYTES=' + repr(sum(pin[1] for pin, raw in rows)),
             'STAGE_PIN=' + repr(STAGE[1:]), 'WIRE_PIN=' + repr((len(wire), digest(wire))),
             'TRAILER=' + repr(trailer), 'STAGE_B64=(\n' + encoded_chunks(stage) + '\n)', 'FRAME_ROWS=(']
    for (pin, raw), encoded in zip(rows, frames):
        lines.append('    ' + repr(pin + (len(encoded),)) + ',')
    lines.append(')')
    program = ('\n'.join(lines) + '\n' + PROGRAM_BODY).encode('ascii')
    if (len(program) > MAX_PROGRAM or len(wire) > MAX_WIRE or
            sum(pin[1] for pin, raw in rows) > MAX_RAW or
            any(len(line) > 256 for line in program.splitlines()) or
            any(len(line) > 256 for line in wire.splitlines())):
        raise ValueError('envelope_budget')
    ast.parse(program.decode('ascii'), feature_version=(3, 5))
    return program, wire


def main():
    if len(sys.argv) != 1:
        raise SystemExit('SOURCE-only: no device/UI/service arguments')
    stamp = time.strftime('%Y%m%d-%H%M%S') + '-' + time.monotonic_ns().__str__()[-8:]
    out = ROOT / 'results' / ('formal-send-stage-source-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-inputs'
    private.mkdir()
    inputs = {}
    report = dict(kind='formal-send-stage-v1-source', source_complete=False, error=None, error_code=None, batches=[],
                  decoded_limit=MAX_RAW, wire_limit=MAX_WIRE, program_limit=MAX_PROGRAM,
                  line_limit=256, device=False, stage_executed=False, boot=False, owner=False,
                  helper=False, receive=False, send=False, rf=False, restoration=False, phone=False)
    try:
        for path, size, sha in CATALOGS + (STAGE,):
            inputs[path] = read_fixed(path, size, sha)
        inputs[SELF] = read_fixed(SELF)
        inputs[CMD] = read_fixed(CMD)
        mapped, files = catalogs(inputs)
        stage_tree = ast.parse(inputs[STAGE[0]].decode('utf-8'), feature_version=(3, 5))
        if literal(stage_tree, 'PROFILE_FILES') != mapped or literal(stage_tree, 'PROFILE_TOTALS') != TOTALS:
            raise ValueError('fixed_profile_mapping')
        if literal(stage_tree, 'RAW_LIMIT') != MAX_RAW or literal(stage_tree, 'MAX_SECONDS') != 120.0:
            raise ValueError('fixed_stage_budget')
        for (profile, root, pins), rows in zip(mapped, files):
            program, wire = make_program(profile, rows, inputs[STAGE[0]])
            with (out / (profile + '.program.py')).open('xb') as handle:
                handle.write(program)
            with (out / (profile + '.wire.raw')).open('xb') as handle:
                handle.write(wire)
            report['batches'].append(dict(profile=profile, files=len(pins), decoded_bytes=sum(pin[1] for pin in pins),
                program_bytes=len(program), program_sha256=digest(program), wire_bytes=len(wire), wire_sha256=digest(wire)))
        report['source_complete'] = True
    except BaseException as error:
        report['error'] = type(error).__name__
        report['error_code'] = error_code(error)
    finally:
        preserved = True
        for path, raw in inputs.items():
            try:
                target = private / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as handle:
                    handle.write(raw)
                if target.read_bytes() != raw or read_fixed(path) != raw:
                    preserved = False
            except BaseException as error:
                preserved = False
                if report['error'] is None:
                    report['error'] = type(error).__name__
                    report['error_code'] = error_code(error)
        report['source_inputs'] = len(inputs)
        report['source_preserved'] = preserved
        report['passed'] = report['source_complete'] and preserved and report['error'] is None
        result = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
        readme = (b'PC SOURCE generation only. Three independent fixed files-only batches; no device transport entry.\n'
                  b'Each decoded batch <=4 MiB, program <=2 MiB, wire <=4 MiB, all lines <=256 bytes.\n'
                  b'No stager/Boot/Owner/native execution. Existing complete target inventories require actual readback.\n'
                  b'Partial/conflicting trees must remain untouched. Private source/payload snapshots are not in this ZIP.\n'
                  b'Future explicit device use needs its own authorization, baseline, raw exits, FD close and readback evidence.\n'
                  b'File source pins and framed end do not grant RF or prove stdin EOF, phone transfer or restoration.\n')
        with (out / 'result.json').open('xb') as handle:
            handle.write(result)
        with (out / 'README.txt').open('xb') as handle:
            handle.write(readme)
        with zipfile.ZipFile(out / 'SOURCE_RESULTS.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('result.json', result)
            archive.writestr('README.txt', readme)
        print(result.decode('ascii').rstrip())
        print('SOURCE_RESULTS=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
