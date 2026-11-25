#!/usr/bin/env python3
"""Independent sender/FileCenter deploy assembly; PC SOURCE default only.

Emits actual fixed EXCL stager programs, their original-180 timer bootstraps and
three separately bounded wires. No target business, tests, ADB or RF is run.
Sender payload bytes are reused in a new sender domain; ordinary is also new.
The observer domain remains unchanged; no existing root is replaced.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
import re
import sys
import time
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ('candidate/formal-send-filecenter-deploy-v3/runtime/formal_send_stage.py',
         37426, '875591a3624181ab3e0a455ac104660e68f261d46c42721f36609dea4baf7f91')
CATALOGS = (
    ('candidate/formal-send-filecenter-deploy-v3/assets/ordinary-source-manifest.json',
     20141, 'e95505b409652150330dbba282cd038c02d978d04378f250310219a71305f37a'),
    ('candidate/formal-send-filecenter-deploy-v3/assets/asset-sources.json',
     23850, '3551b5e546aa27e6d68e664b787ffd500e3992fd6f4d93bc7dc28291021c22fa'),
    ('candidate/formal-send-v1/assets/sender-source-manifest.json',
     3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
)
SELF = 'host/formal_send_filecenter_deploy_v3_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FILECENTER_DEPLOY_V3_SOURCE_CHECK.cmd'
TOTALS = (('sender', 27, 2402458), ('observer', 41, 1440449), ('ordinary', 37, 1346351))
MAX_PROGRAM = 2 * 1024 * 1024
MAX_RAW = MAX_WIRE = 4 * 1024 * 1024
LINE = 96
ERROR_CODES = frozenset(('source_path', 'source_pin', 'source_literal', 'catalog_shape',
    'sender_manifest', 'batch_shape', 'target_shape', 'target_mode', 'source_changed',
    'shared_deployment', 'envelope_budget', 'fixed_profile_mapping', 'fixed_stage_budget',
    'graph_contract', 'filecenter_contract', 'bootstrap_contract', 'source_preserved', 'snapshot'))

DEPLOY_ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v3'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v3'
BASE_GENERATOR = ('host/formal_send_stage_source_check.py', 17979,
    'db79f3f1b7ef7ac3dc1fb92865d4d2583a7539f7c5cd62be3a3537d55c52d45c')
BASE_BOOTSTRAP = ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py',
    13207, 'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d')
BASE_ENVELOPE = ('host/formal_send_stage_bootstrap_source_check.py', 19997,
    'aede2e43410f7f3a78fb715c077e567da84ba47d9dfa9c5d4290e3b8795b60d3')
FC_MANIFEST = ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json',
    2466, '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')


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
    if (ordinary['schema'] != 'p011-formal-send-filecenter-deploy-v3-ordinary-source-catalog' or
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
        ('ordinary', '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v3',
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


def graph_contracts(inputs):
    ordinary = json.loads(inputs[CATALOGS[0][0]])
    trees = {}
    for row in ordinary['sources'] + ordinary['startup_sources']:
        if row['source'].startswith('candidate/formal-send-filecenter-deploy-v3/runtime/'):
            trees[row['module']] = ast.parse(inputs[row['source']].decode('utf-8'), feature_version=(3, 5))
    if set(trees) != {'mta_send_trial', 'mta_send_terminal_consumer', 'mta_service',
                      'mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session',
                      'mta_go_send_publication'}:
        raise ValueError('graph_contract')
    boot, owner, outer = (trees[name] for name in
                         ('mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session'))
    pins = tuple((row['module'], row['bytes'], row['sha256']) for row in ordinary['sources'])
    startup = {row['module']: (row['bytes'], row['sha256']) for row in ordinary['startup_sources']}
    if (literal(boot, 'SOURCE_PINS') != pins or literal(boot, 'ROOT') != DEPLOY_ROOT or
            literal(boot, 'PHYSICAL_ROOT') != PHYSICAL_ROOT or literal(boot, 'LOAD_SECONDS') != 10.0 or
            literal(boot, 'GO_ASSET_ROOT') != '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets' or
            literal(boot, 'SOURCE_SCHEMA') != 'p011-formal-send-v1-source' or
            literal(owner, 'ROOT') != DEPLOY_ROOT or literal(owner, 'BOOT_PIN') != startup['mta_client_receive_boot'] or
            literal(owner, 'BOOT_MODULES') != tuple(row[0] for row in pins) or
            literal(outer, 'ROOT') != DEPLOY_ROOT or literal(outer, 'PHYSICAL_ROOT') != PHYSICAL_ROOT or
            literal(outer, 'BOOT_PIN') != startup['mta_client_receive_boot'] or
            literal(outer, 'OWNER_PIN') != startup['mta_client_service_owner'] or
            literal(trees['mta_send_trial'], 'ROOT') != DEPLOY_ROOT + '/runtime' or
            literal(trees['mta_send_terminal_consumer'], 'ROOT') != DEPLOY_ROOT + '/runtime' or
            literal(trees['mta_service'], '_GO_STATE_ROOT') != DEPLOY_ROOT or
            literal(trees['mta_go_send_publication'], 'ASSET_ROOT') !=
                '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets' or
            literal(trees['mta_go_send_publication'], 'BUNDLE_MANIFEST_SHA') !=
                CATALOGS[2][2]):
        raise ValueError('graph_contract')
    owner_raw = inputs[next(row['source'] for row in ordinary['startup_sources']
                            if row['module'] == 'mta_client_service_owner')]
    if PHYSICAL_ROOT.encode('ascii') not in owner_raw or b'p011-mta-formal-send-v1' in owner_raw:
        raise ValueError('graph_contract')
    fc = json.loads(inputs[FC_MANIFEST[0]])
    fc_pins = tuple((row['module'], row['bytes'], row['sha256']) for row in fc['sources'])
    if (fc['schema'] != 'p011-formal-send-filecenter-deploy-v3-filecenter-source' or
            fc['source_count'] != 9 or len(fc['sources']) != 9 or fc['source_bytes'] != 99972 or
            fc['source_cap'] != 131072 or fc['in_protocol_stage_payload'] is not False or
            literal(owner, 'FILECENTER_PINS') != fc_pins or literal(owner, 'FILECENTER_MAX_SOURCE') != 131072):
        raise ValueError('filecenter_contract')
    close_methods = [node for cls in owner.body if isinstance(cls, ast.ClassDef) and cls.name == 'FixedStateServiceOwner'
                     for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '_close_filecenter']
    close_calls = [node for method in close_methods for node in ast.walk(method) if isinstance(node, ast.Call) and
                   isinstance(node.func, ast.Subscript) and
                   isinstance(node.func.slice, ast.Constant) and node.func.slice.value == 'close']
    if (len(close_methods) != 1 or len(close_calls) != 1 or len(close_calls[0].keywords) != 1 or
            close_calls[0].keywords[0].arg != 'cleanup_until' or
            not isinstance(close_calls[0].keywords[0].value, ast.Attribute) or
            close_calls[0].keywords[0].value.attr != '_cleanup_until_original' or
            not isinstance(close_calls[0].keywords[0].value.value, ast.Name) or
            close_calls[0].keywords[0].value.value.id != 'self' or
            fc.get('parent_deadline_crop_integrated') is not True):
        raise ValueError('filecenter_contract')
    for row in fc['sources']:
        inputs[row['source']] = read_fixed(row['source'], row['bytes'], row['sha256'])
    if sum(len(inputs[row['source']]) for row in fc['sources']) != 99972:
        raise ValueError('filecenter_contract')
    if literal(ast.parse(inputs[BASE_GENERATOR[0]].decode('utf-8')), 'PROGRAM_BODY') != PROGRAM_BODY:
        raise ValueError('bootstrap_contract')
    return ordinary, fc


def replace_assignment(raw, name, value, multiline=False):
    source = raw.decode('ascii')
    tree = ast.parse(source, feature_version=(3, 5))
    rows = [node for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(rows) != 1:
        raise ValueError('bootstrap_contract')
    lines = source.splitlines(True)
    replacement = (name + ' = (\n' + ''.join('    ' + repr(row) + ',\n' for row in value) + ')\n'
                   if multiline else name + ' = ' + repr(value) + '\n')
    lines[rows[0].lineno - 1:rows[0].end_lineno] = [replacement]
    return ''.join(lines).encode('ascii')


def bootstrap_parts(programs, wires, wrapper_raw):
    program_pins = tuple((profile, len(raw), digest(raw)) for profile, raw in programs)
    wire_pins = tuple((profile, len(raw), digest(raw)) for profile, raw in wires)
    lines = ['"""Fixed three-program data only; no loader or staging side effects."""', 'PROGRAM_ROWS=(']
    for profile, raw in programs:
        lines += ['    (' + repr(profile) + ', ' + str(len(raw)) + ', ' + repr(digest(raw)) + ', (',
                  encoded_chunks(raw), '    )),']
    lines.append(')')
    data = ('\n'.join(lines) + '\n').encode('ascii')
    data_pin = (len(data), digest(data))
    for name, value, multiline in (
            ('DATA_PIN', data_pin, False), ('STAGE_PIN', STAGE[1:], False),
            ('PROGRAM_PINS', program_pins, True), ('WIRE_PINS', wire_pins, True)):
        wrapper_raw = replace_assignment(wrapper_raw, name, value, multiline)
    # FixedStage.close_row preserves its REAL errno9 fstat reply in close_error.
    # Reject every other error; still recheck the original fd in the passive consumer.
    old = (b"row.get('close_return') is not None or row.get('close_error') is not None or\n"
           b"                row.get('ebadf') is not True")
    new = (b"row.get('close_return') is not None or\n"
           b"                not isinstance(row.get('close_error'), OSError) or\n"
           b"                row['close_error'].errno != errno.EBADF or row.get('ebadf') is not True")
    if wrapper_raw.count(old) != 1:
        raise ValueError('bootstrap_contract')
    wrapper_raw = wrapper_raw.replace(old, new)
    for raw in (data, wrapper_raw):
        if len(raw) > MAX_PROGRAM or any(len(line) > 256 for line in raw.splitlines()):
            raise ValueError('envelope_budget')
        ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    tree = ast.parse(wrapper_raw.decode('ascii'), feature_version=(3, 5))
    if (literal(tree, 'OUTER_SECONDS') != 180.0 or literal(tree, 'INNER_SECONDS') != 120.0 or
            literal(tree, 'STAGE_PIN') != STAGE[1:] or literal(tree, 'PROGRAM_PINS') != program_pins or
            literal(tree, 'WIRE_PINS') != wire_pins or literal(tree, 'DATA_PIN') != data_pin):
        raise ValueError('bootstrap_contract')
    return data, wrapper_raw


def bootstrap_program(profile, data, wrapper, envelope):
    lines = ['PROFILE=' + repr(profile), "DATA_MODULE='formal_send_stage_bootstrap_programs'",
             'DATA_PIN=' + repr((len(data), digest(data))), 'WRAPPER_PIN=' + repr((len(wrapper), digest(wrapper))),
             'DATA_B64=(', encoded_chunks(data), ')', 'WRAPPER_B64=(', encoded_chunks(wrapper), ')']
    raw = ('\n'.join(lines) + '\n' + envelope).encode('ascii')
    if len(raw) > MAX_PROGRAM or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('envelope_budget')
    ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return raw


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('snapshot')
        handle.flush()
        os.fsync(handle.fileno())
    if path.read_bytes() != raw:
        raise ValueError('snapshot')


def main():
    if len(sys.argv) != 1:
        print('PC SOURCE only; no --check-device/--ui/profile or arbitrary source input')
        return 2
    stamp = time.strftime('%Y%m%d-%H%M%S') + '-' + str(time.monotonic_ns())[-8:]
    out = ROOT / 'results' / ('formal-send-filecenter-deploy-source-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    inputs, outputs = {}, {}
    report = dict(kind='formal-send-filecenter-deploy-v3-source', passed=False,
        source_complete=False, source_preserved=False, error_code=None, source_inputs=0, batches=[],
        fixed_new_root=DEPLOY_ROOT, ordinary_count=32, ordinary_files=37,
        decoded_limit=MAX_RAW, wire_limit=MAX_WIRE, program_limit=MAX_PROGRAM, line_limit=256,
        outer_seconds=180, inner_seconds=120, filecenter_source_count=9, filecenter_source_bytes=99972,
        filecenter_source_cap=131072, filecenter_in_protocol_payload=False, filecenter_parent_deadline_crop_integrated=True,
        new_graph_ast_count=0, new_stager_ast_count=0, new_program_ast_count=0,
        new_bootstrap_ast_count=0, device=False, stage_executed=False, graph_executed=False,
        boot=False, owner=False, filecenter=False, guardian=False, helper=False, rf=False,
        restoration=False, phone=False, production=False, physical_stdin_eof_verified=False)
    try:
        for path, size, sha in CATALOGS + (STAGE, BASE_GENERATOR, BASE_BOOTSTRAP, BASE_ENVELOPE, FC_MANIFEST):
            inputs[path] = read_fixed(path, size, sha)
        inputs[SELF], inputs[CMD] = read_fixed(SELF), read_fixed(CMD)
        mapped, files = catalogs(inputs)
        stage_tree = ast.parse(inputs[STAGE[0]].decode('utf-8'), feature_version=(3, 5))
        if (literal(stage_tree, 'PROFILE_FILES') != mapped or literal(stage_tree, 'PROFILE_TOTALS') != TOTALS or
                literal(stage_tree, 'RAW_LIMIT') != MAX_RAW or literal(stage_tree, 'MAX_SECONDS') != 120.0):
            raise ValueError('fixed_profile_mapping')
        graph, fc = graph_contracts(inputs)
        report.update(new_graph_ast_count=7, new_stager_ast_count=1)
        programs, wires = [], []
        for (profile, root, pins), rows in zip(mapped, files):
            program, wire = make_program(profile, rows, inputs[STAGE[0]])
            programs.append((profile, program))
            wires.append((profile, wire))
            outputs[profile + '.program.py'], outputs[profile + '.wire.raw'] = program, wire
        data, wrapper = bootstrap_parts(programs, wires, inputs[BASE_BOOTSTRAP[0]])
        envelope = literal(ast.parse(inputs[BASE_ENVELOPE[0]].decode('ascii')), 'ENVELOPE')
        outputs['bootstrap-programs.py'], outputs['bootstrap-wrapper.py'] = data, wrapper
        for (profile, program), (_, wire), (_, _, pins) in zip(programs, wires, mapped):
            bootstrap = bootstrap_program(profile, data, wrapper, envelope)
            outputs[profile + '.bootstrap.py'] = bootstrap
            report['batches'].append(dict(profile=profile, files=len(pins), decoded_bytes=sum(pin[1] for pin in pins),
                program_bytes=len(program), program_sha256=digest(program), wire_bytes=len(wire), wire_sha256=digest(wire),
                bootstrap_bytes=len(bootstrap), bootstrap_sha256=digest(bootstrap)))
        # The UI later supplies these exact nine original source bytes to Owner.create_filecenter.
        # They are NOT staged protocol modules, a UI window or guardian substitute.
        for row in fc['sources']:
            outputs['filecenter-sources/' + row['module'] + '.py'] = inputs[row['source']]
        outputs['filecenter-sources/source-manifest.json'] = inputs[FC_MANIFEST[0]]
        for name, raw in outputs.items():
            write_new(out / name, raw)
        report.update(source_complete=True, new_program_ast_count=3, new_bootstrap_ast_count=5)
    except BaseException as error:
        report['error_code'] = error_code(error)
    preserved = bool(inputs) and report['source_complete']
    inventory = {}
    for path, raw in inputs.items():
        try:
            write_new(out / 'private-inputs' / path, raw)
            inventory[path] = dict(bytes=len(raw), sha256=digest(raw))
            if read_fixed(path) != raw:
                preserved = False
        except BaseException:
            preserved = False
    for name, raw in outputs.items():
        if not (out / name).exists() or (out / name).read_bytes() != raw:
            preserved = False
    write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['source_inputs'], report['source_preserved'] = len(inputs), preserved
    report['passed'] = report['source_complete'] and preserved and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'PC SOURCE assembly only. New unique sender asset and ordinary deployment roots; no old inventory replacement.\n'
        b'Three fixed EXCL files-only target stages reuse payload sources and the original observer domain/caps.\n'
        b'Each raw/wire <=4MiB, program/bootstrap <=2MiB, lines <=256, inner120/outer180; no cap increase.\n'
        b'Use the fixed profile bootstrap with its corresponding wire for explicit separately authorized staging.\n'
        b'No --check-device path exists here. No stager/Boot/Owner/business/native/RF/phone/UI/guardian is executed.\n'
        b'Trailer proves framed end, not physical stdin EOF. Unknown resources/timer remain pending.\n'
        b'Bootstrap consumes actual errno9 close readback plus original fd EBADF; other errors are not accepted.\n'
        b'FC9 source files are a separate fixed UI caller supply, not protocol payload or guardian/restore evidence.\n'
        b'FileCenter close receives the original Owner cleanup cap; nested waits are clipped without renewal.\n'
        b'This SOURCE assembly is not actual shutdown/Native restoration or production transfer evidence.\n'
        b'Private programs/wires/source bytes stay local. Public ZIP contains only result and README.\n')
    write_new(out / 'result.json', result)
    write_new(out / 'README.txt', readme)
    trace = b'SOURCE_DECISION=' + (b'0' if report['passed'] else b'1') + b'\nNOT_RUN_DEVICE\nNOT_RUN_BUSINESS\n'
    write_new(out / 'source-trace.raw', trace)
    with zipfile.ZipFile(out / 'SOURCE_RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'SOURCE_RESULTS.zip') as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None:
            raise ValueError('snapshot')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out)), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
