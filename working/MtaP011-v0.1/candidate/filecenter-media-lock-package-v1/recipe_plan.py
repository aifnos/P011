"""Pinned PC-only mutex integration plan, NOT a finished package emitter.

prepare() reads fixed current send/prepare20 metadata and real FC9 bytes only.
It returns ({}, facts, inputs): the empty output set is deliberate and cannot
be described as an assembled graph. --write refuses before any preparation or
filesystem write. Root must review and finish the independent receive defs
validator/emitter before a separately frozen publication is possible.
No old prepare/verify/main/test, runtime import, subprocess or ADB is invoked.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
ROOT = 'candidate/filecenter-media-lock-package-v1'
SELF = ROOT + '/recipe_plan.py'
SEND_ROOT_BEFORE = 'p011-mta-formal-send-filecenter-httpcp-v1'
SEND_ROOT_AFTER = 'p011-mta-formal-send-filecenter-mutex1-v1'
RECEIVE_ROOT_BEFORE = 'p011-mta-rx-prep20-v001'
RECEIVE_ROOT_AFTER = 'p011-mta-rx-mlock1-v001'
FC_CAP = 131072
PAYLOAD_CAP = 4194304
PAYLOAD_BYTES = 4193768
SEND_ORDINARY_BYTES = 1368142
CURRENT = (
    ('candidate/formal-send-fc-http-cap-v1/generate_package.py', 33030,
     'd949a5d68efd0d4d29a47412feb99a61bed1c9e058716e02522678d7aad7b91d'),
    ('candidate/formal-send-fc-http-cap-v1/generation.json', 27597,
     'a2bdae7d8e32c90e8f8926388fd1156c5c3169d1a41b0220f12895324ea33fb1'),
    ('candidate/formal-send-fc-http-cap-v1/assets/filecenter-source-manifest.json', 2476,
     '819879157ba075d1afeb5bfad88e911408f5b060402166199c67b4b654a1d8a5'),
    ('candidate/formal-send-fc-http-cap-v1/assets/ordinary-source-manifest.json', 20762,
     '6a478fc8bc8a61db8d43d1e89d10d1363c76fc3762fa51500dbe95539d794802'),
    ('candidate/receive-startup-20s-graph-v1/generate_graph.py', 41819,
     'e3b690ff769187c48d87448198371d8025ed8fcdd9ae78678f8e17cf56e338d8'),
    ('host/formal_receive_startup_20s_v1_definitions.py', 297239,
     '49a56e7e809f2f515ca66735a38adf68d162aea1697e8d6a17cd74d0f68c61ca'),
    ('candidate/receive-startup-20s-graph-v1/graph-generation.json', 4018,
     '050b47d1ef6e28035f84d446a098279785fd55cda487cd0c514eb25c575dc563'),
    ('host/formal_receive_startup_20s_v1_definition_manifest.json', 7937,
     'b33bf4d703603691b4751ccc5a632cbb248c773a6e757f0687c476aae6d74503'),
    ('host/formal_receive_startup_20s_v1_private_source_manifest.json', 8165,
     '94e9344d76d96891b61177ac23b6ace4aa67e7754fd5e8df94288079a89fcfde'),
    ('candidate/filecenter-media-lock-deadline-v1/generate_candidate.py', 10637,
     'e7e2b8e4d82e2efc8bb5bca10f9415227f946a197976cd58b9c9c26b0ad0059b'),
)
MUTEX = {
    'send': (
        ('candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py', 27656,
         '57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd'),
        ('candidate/filecenter-media-lock-deadline-v1/send/exactsource-delta.json', 4751,
         '690bbf7a2d8e79529567e4eba34086ff498020a9167be51d3ee306c9f7e710a6')),
    'receive': (
        ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py', 35198,
         '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca'),
        ('candidate/filecenter-media-lock-deadline-v1/receive/exactsource-delta.json', 4760,
         '8f5d938dd5aac90374b1cf8be999756e35ba645e11f362c8726ad24c388cea35')),
}
METHODS = ('_FileCenterHandler.dispatch', '_FileCenterHandler.media',
           '_Companion.open_file', '_Companion.media_row', '_Companion.audio_source_fd')
ADDED = ('_MediaLock.__init__', '_MediaLock.__enter__', '_MediaLock.__exit__')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(inputs, row):
    name, size, sha = row
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None and
         all(part not in ('', '.', '..') for part in name.split('/')) and
         not name.startswith('/') and type(size) is int and 0 < size <= 2097152 and
         type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha) is not None, 'fixed_plan_pin')
    target = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        info = node.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
             not getattr(info, 'st_file_attributes', 0) & 0x400, 'plan_base_identity')
    for index, part in enumerate(name.split('/')):
        target = target / part
        info = target.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'plan_source_reparse')
        if index < len(name.split('/')) - 1:
            need(stat.S_ISDIR(info.st_mode), 'plan_source_ancestor')
    need(stat.S_ISREG(info.st_mode) and info.st_size == size, 'plan_source_file')
    before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    with target.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        need(identity == before, 'plan_source_open_identity')
        raw = handle.read(size + 1)
        held = os.fstat(handle.fileno())
        need((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns) == identity,
             'plan_source_held_changed')
    after = target.lstat()
    need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == before and
         (len(raw), digest(raw)) == (size, sha), 'plan_actual_source_pin')
    need(name not in inputs or inputs[name] == raw, 'plan_input_collision')
    inputs[name] = raw
    return raw


def literal(raw, name):
    rows = [node for node in ast.parse(raw.decode('ascii')).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'plan_unique_literal')
    return ast.literal_eval(rows[0].value)


def function_rows(raw):
    lines, values = raw.splitlines(keepends=True), {}
    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef)):
                name = '.'.join(prefix + (child.name,))
                if isinstance(child, ast.FunctionDef):
                    need(name not in values, 'plan_unique_definition')
                    values[name] = b''.join(lines[child.lineno - 1:child.end_lineno])
                walk(child, prefix + (child.name,))
            else:
                walk(child, prefix)
    walk(ast.parse(raw.decode('utf-8'), feature_version=(3, 5)), ())
    return values


def mutex_inverse(inputs, side, before_pin):
    candidate_pin, delta_pin = MUTEX[side]
    before = read_pin(inputs, before_pin)
    after = read_pin(inputs, candidate_pin)
    delta = json.loads(read_pin(inputs, delta_pin).decode('ascii'))
    need(delta['schema'] == 'filecenter-media-lock-deadline-v1-exactsource-delta' and
         delta['side'] == side and delta['origin'] == dict(
             path=before_pin[0], bytes=before_pin[1], sha256=before_pin[2]) and
         delta['candidate'] == dict(path=candidate_pin[0], bytes=candidate_pin[1], sha256=candidate_pin[2]) and
         tuple(delta['changed_methods']) == METHODS and tuple(delta['added_methods']) == ADDED and
         len(delta['replacements']) == 8 and len(after) - len(before) == 1568, 'plan_mutex_actual_delta')
    forward, inverse = before, after
    for step in delta['replacements']:
        old, new = step['before'].encode('ascii'), step['after'].encode('ascii')
        need(step['count'] == 1 and forward.count(old) == 1, 'plan_mutex_forward_anchor')
        forward = forward.replace(old, new, 1)
    for step in reversed(delta['replacements']):
        old, new = step['before'].encode('ascii'), step['after'].encode('ascii')
        need(inverse.count(new) == 1, 'plan_mutex_inverse_anchor')
        inverse = inverse.replace(new, old, 1)
    need(forward == after and inverse == before and
         ast.dump(ast.parse(inverse.decode('utf-8')), include_attributes=True) ==
         ast.dump(ast.parse(before.decode('utf-8')), include_attributes=True), 'plan_mutex_whole_inverse')
    original, current = function_rows(before), function_rows(after)
    need(set(current) == set(original) | set(ADDED) and
         {name for name in original if original[name] != current[name]} == set(METHODS),
         'plan_mutex_only_five_methods')
    need(all(original[name] == current[name] for name in
         ('create', '_owner_binding', '_Companion.check', '_Companion.close', '_Companion.closed')),
         'plan_mutex_authority_close_unchanged')
    return candidate_pin


def fc_rows(inputs, rows, side, original_total):
    need(type(rows) is tuple and len(rows) == 9 and len({row[0] for row in rows}) == 9 and
         all(type(row) is tuple and len(row) == 4 for row in rows) and
         sum(row[2] for row in rows) == original_total, 'plan_original_fc9')
    for name, path, size, sha in rows:
        read_pin(inputs, (path, size, sha))
    companion = next(row for row in rows if row[0] == 'mta_filecenter_companion')
    candidate = mutex_inverse(inputs, side, companion[1:])
    planned = tuple((row[0],) + candidate if row[0] == companion[0] else row for row in rows)
    total = sum(row[2] for row in planned)
    need(sum(old != new for old, new in zip(rows, planned)) == 1 and
         total == original_total + 1568 <= FC_CAP and all(
             old == new for old, new in zip(rows, planned) if old[0] != companion[0]), 'plan_only_one_fc_source')
    return planned, total


def prepare():
    """SOURCE plan only; outputs are deliberately empty until emitter closure."""
    need(len(SEND_ROOT_BEFORE) == len(SEND_ROOT_AFTER) and
         len(RECEIVE_ROOT_BEFORE) == len(RECEIVE_ROOT_AFTER) and
         SEND_ROOT_BEFORE != SEND_ROOT_AFTER and RECEIVE_ROOT_BEFORE != RECEIVE_ROOT_AFTER,
         'plan_equal_length_independent_roots')
    inputs = {}
    for row in CURRENT:
        read_pin(inputs, row)
    send, fc, ordinary = (json.loads(inputs[CURRENT[index][0]].decode('utf-8')) for index in (1, 2, 3))
    definitions = inputs[CURRENT[5][0]]
    receive = json.loads(inputs[CURRENT[6][0]].decode('ascii'))
    need(send['filecenter_source_bytes'] == fc['source_bytes'] == 100114 and
         fc['source_count'] == 9 and fc['source_cap'] == FC_CAP and
         fc['in_protocol_stage_payload'] is False and send['ordinary_batch_files'] == 37 and
         send['ordinary_batch_bytes'] == ordinary['ordinary_batch_bytes'] == SEND_ORDINARY_BYTES and
         send['unchanged_sender_assets'] == 27 and send['unchanged_observer_assets'] == 41 and
         send['reused_gui_files'] == 19 and send['reused_gui_bytes'] == 4185296, 'plan_current_send')
    receive_rows = literal(definitions, 'FILECENTER_SOURCES')
    payload = literal(definitions, 'ORDINARY_ROWS') + literal(definitions, 'HELPERS') + \
        literal(definitions, 'PRIVATE_ROWS') + (literal(definitions, 'WPA'), literal(definitions, 'MONITOR'))
    need(len(payload) == len({row[0] for row in payload}) == 75 and
         sum(row[2] for row in payload) == literal(definitions, 'PAYLOAD_BYTES') ==
         receive['payload_bytes'] == PAYLOAD_BYTES and receive['payload_remaining'] == 536 and
         receive['root'] == literal(definitions, 'ROOT_AFTER') == RECEIVE_ROOT_BEFORE and
         len(literal(definitions, 'ORIGIN_SOURCE_PINS')) == receive['source_origin_count'] == 304 and
         receive['startup_prepare_seconds_after'] == 20.0 and receive['business_byte_delta'] == 0 and
         receive['inherited_owner_scope_fc_http_provenance_preserved'] is True,
         'plan_current_prepare20_not_old_http_graph')
    send_rows = tuple((row['module'], row['source'], row['bytes'], row['sha256']) for row in fc['sources'])
    new_send, send_total = fc_rows(inputs, send_rows, 'send', 100114)
    new_receive, receive_total = fc_rows(inputs, receive_rows, 'receive', 113832)
    need((send_total, receive_total) == (101682, 115400), 'plan_exact_mutex_fc9_totals')
    staged = [row for row in ordinary['sources'] + ordinary['startup_sources'] + ordinary['helper_sources']
              if row.get('reused_sender_asset') is not True]
    need(len(staged) == 37 and sum(row['bytes'] for row in staged) == SEND_ORDINARY_BYTES and
         all(row.get('module') != 'mta_filecenter_companion' for row in staged) and
         all(row[0] != 'mta_filecenter_companion' for row in payload), 'plan_separate_fc9_not_payload')
    facts = dict(schema='filecenter-media-lock-package-v1-plan', status='PLAN_ONLY_EMITTER_NOT_CLOSED',
        emitter_ready=False, outputs_assembled=False, planned_output_count=None, actual_output_count=0,
        independent_root_lengths_verified=True, planned_send_root=SEND_ROOT_AFTER,
        planned_receive_root=RECEIVE_ROOT_AFTER, receive_current_definitions=list(CURRENT[5]),
        receive_payload_bytes_current=PAYLOAD_BYTES, receive_payload_cap=PAYLOAD_CAP,
        receive_payload_spare_current=536, receive_payload_bytes_after_not_yet_measured=True,
        sender_ordinary_files=37, sender_ordinary_bytes_current=SEND_ORDINARY_BYTES,
        sender_ordinary_bytes_after_not_yet_measured=True, send_fc9=list(new_send), receive_fc9=list(new_receive),
        send_fc9_bytes=send_total, receive_fc9_bytes=receive_total, filecenter_cap=FC_CAP,
        send_fc9_spare=FC_CAP - send_total, receive_fc9_spare=FC_CAP - receive_total,
        current_fc8_bytes_and_pins_retained=True, actual_two_mutex_source_inverse_checked=True,
        declared_receive_flat304_not_whole_parent_validator=True,
        inherited_prepare20_cache_source_preservation_planned_not_new_verified=True,
        sender27_observer41_gui19_reuse_planned=True, new_assets_generated=False,
        source_graph_integrated=False, current_graph_or_source_changed=False,
        new_runtime_outputs_generated=False, old_prepare_verify_main_tests_called=False,
        runtime_imported=False, adb=False, device=False, staged=False, rf=False, phone=False,
        blockers=[
            'New receive defs must replace the old FC9==ORIGINAL_FILECENTER_ROWS gate with an exact one-source mutex inverse.',
            'Retain current304/current11 and inherited Owner/Scope/HTTP/cache/prepare20 provenance without executing old verify/main.',
            'Emit complete six-role root/pin, manifest, Runner and defs closures with whole-byte/position-AST inverse receipts.',
            'Emit send Owner/Outer/Worker/catalog/Stage closures; same-length bytes and payload totals require actual readback.',
            'Freeze the complete independent emitter and focused HOST evidence before any explicit publication.'])
    return {}, facts, inputs


def write_outputs(outputs, inputs):
    # A draft cannot create partial new graphs. The final emitter is not present.
    raise ValueError('package_emitter_not_closed_no_writes')


def main():
    need(sys.argv[1:] in ([], ['--write']), 'plan_source_or_explicit_write')
    if sys.argv[1:] == ['--write']:
        raise ValueError('package_emitter_not_closed_no_writes')
    outputs, facts, inputs = prepare()
    need(outputs == {} and facts['emitter_ready'] is False, 'plan_not_a_package')
    print(json.dumps(facts, sort_keys=True, ensure_ascii=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
