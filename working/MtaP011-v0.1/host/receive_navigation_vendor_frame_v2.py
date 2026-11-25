"""Strict observed vendor presentation envelope, frozen original receipt rules.

Only derived bytes are canonicalized. No clock, device, business or raw write.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import types

BASE = Path(__file__).resolve().parents[1]
ORIGIN = ('host/device_formal_receive_filecenter_navigation_anchor_v1_check.py', 24423,
          '0e9f182b8ff01d8de0020fb3513ddd7b08fd4a33d0d58b10e62543d0ce559e42')
MARKER = b'P011_MTA NAVIGATION_QTTEST_V1'
LEGACY = re.compile(rb'(?P<open>\x1b\[(?:31|37)m)?(?:qml: )?' + MARKER +
    rb' (?P<payload>\{[^\r\n\x1b]{1,2048}\})(?P<close>\x1b\[0m)?\n')
VENDOR = re.compile(
    rb'(?P<open>\x1b\[37m)? \[(?P<month>[0-9]{2})-(?P<day>[0-9]{2}) '
    rb'(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2}):(?P<ms>[0-9]{3})\] '
    rb'\[(?P<source>NavigationTest\.qml|FormalEntry\.qml)\] \[(?P<line>37|19)\] '
    + MARKER + rb' (?P<payload>\{[^\r\n\x1b]{1,2048}\}) (?P<close>\x1b\[0m)?\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def load_original():
    raw = (BASE / ORIGIN[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == ORIGIN[1:], 'navigation_origin_pin')
    tree = ast.parse(raw, feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, ast.FunctionDef) and
             row.name in ('need', 'navigation_receipt')]
    need(tuple(row.name for row in nodes) == ('need', 'navigation_receipt'), 'navigation_origin_functions')
    module = types.ModuleType('frozen_navigation_receipt_rules')
    module.__dict__.update(json=json, re=re)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BASE / ORIGIN[0]), 'exec'), module.__dict__)
    need('main' not in module.__dict__, 'navigation_old_main_forbidden')
    return module.navigation_receipt


ORIGINAL = load_original()


def canonicalize(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4194304, 'navigation_log_bound')
    need(raw.count(MARKER) == 1, 'navigation_frame_count')
    normalized = raw.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
    rows = [row for row in normalized.splitlines(keepends=True) if MARKER in row]
    need(len(rows) == 1 and rows[0].endswith(b'\n') and len(rows[0]) <= 2304,
         'navigation_frame_complete')
    row = rows[0]
    legacy = LEGACY.fullmatch(row)
    if legacy is not None:
        # Match raw structure before the frozen rule can remove any control code.
        need(bool(legacy['open']) == bool(legacy['close']), 'navigation_legacy_ansi_pair')
        return raw, None
    frame = VENDOR.fullmatch(row)
    need(frame is not None, 'navigation_vendor_format')
    need(bool(frame['open']) == bool(frame['close']), 'navigation_vendor_ansi_pair')
    source, line = frame['source'], frame['line']
    need((source, line) in ((b'NavigationTest.qml', b'37'), (b'FormalEntry.qml', b'19')),
         'navigation_vendor_source')
    month, day = int(frame['month']), int(frame['day'])
    days = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    need(1 <= month <= 12 and 1 <= day <= days[month - 1] and
         0 <= int(frame['hour']) <= 23 and 0 <= int(frame['minute']) <= 59 and
         0 <= int(frame['second']) <= 59, 'navigation_vendor_timestamp')
    canonical = MARKER + b' ' + frame['payload'] + b'\n'
    need(normalized.count(row) == 1, 'navigation_vendor_row_identity')
    return normalized.replace(row, canonical, 1), source


def navigation_receipt(raw):
    canonical, source = canonicalize(raw)
    value = ORIGINAL(canonical)
    # FormalEntry/19 is a failure-only emitter. It cannot attest success.
    need(source in (None, b'NavigationTest.qml'), 'navigation_vendor_success_emitter')
    return value
