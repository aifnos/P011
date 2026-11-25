"""Thin read-only Receive UI-v1 ready watch followed immediately by DRM capture.

Only two fixed path bindings and finite labels change in the proven v7 watcher.
No UI launch, input, RF, credentials, closure receipt or old watcher main runs
while loading definitions. Default mode is PC syntax only; --check-device is
the original finite observer. A stale READY needs the exact candidate live.
"""
import argparse
import ast
import datetime
import hashlib
from pathlib import Path
import secrets
import subprocess
import sys
import types

BASE = Path(__file__).resolve().parents[1]
WATCHER = ('host/capture_formal_ui_v7_ready.py', 3650,
           'd3b6934a6b1b1a099345153d615d5cc9ae9c42cb646685187cb8c10e6a5c3c69')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
SESSION = '2c3d526c2d034da16e6c4a61'


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('observer_source_pin')
    return raw


def main():
    raw = read_pin(WATCHER)
    tree = ast.parse(raw.decode('utf-8'))
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
            row.targets[0].id == 'WATCH']
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    if len(rows) != 1 or len(functions) != 1 or functions[0].decorator_list:
        raise ValueError('observer_definition')
    watch = ast.literal_eval(rows[0].value)
    old = 'a44b98dd639095d9063c9e1a'
    if watch.count(old) != 2 or watch.count('-formal-send-filecenter-ui-v7') != 1:
        raise ValueError('observer_path_count')
    watch = watch.replace(old, SESSION).replace('-formal-send-filecenter-ui-v7', '-formal-receive-ui-v1')
    ast.parse(watch, feature_version=(3, 5))
    transport = types.ModuleType('fixed_receive_ui_ready_transport')
    transport.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(read_pin(TRANSPORT), transport.__file__, 'exec'), transport.__dict__)
    scope = dict(__name__='fixed_receive_ui_ready', __doc__=__doc__, BASE=BASE, WATCH=watch,
                 argparse=argparse, ast=ast, datetime=datetime, Path=Path,
                 secrets=secrets, subprocess=subprocess, sys=sys, Adb=transport.Adb)
    # Finite result labels only; original observer/DRM sequencing is retained.
    node_source = ast.get_source_segment(raw.decode('utf-8'), functions[0])
    node_source = node_source.replace('UI_V7_', 'UI_RECEIVE_V1_').replace(
        'ui-v7-ready-readonly-', 'ui-receive-v1-ready-readonly-').replace(
        'fixed-v7-ui-ready-readonly', 'fixed-receive-v1-ui-ready-readonly')
    node = ast.parse(node_source).body[0]
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 '<fixed-receive-ui-ready-main>', 'exec'), scope)
    return scope['main']()


if __name__ == '__main__':
    raise SystemExit(main())
