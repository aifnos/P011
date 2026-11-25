"""Isolated v20 private IPv4 projection; default PC SOURCE only.

Reuse the whole-SHA-frozen v17 readonly profile. Only four exact mta_ip
record types gain named private fields. No query, admission or RF change.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import types

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
V17 = BASE / 'host/client_readonly_diagnostic_v17_p011.py'
V17_SHA = 'e2bd556d9d10fb80aeb2a2748837991336a0ba88f802635fad97d03d2cfa9a11'
PROFILE = BASE / 'host/client_baseline_v3_performance_p011.py'
PROFILE_SHA = 'c2077c53c20ef3b6eb1dfc6d2d7a0658807f95569bfb6bd76b8df25155a19a3c'
_PROFILE = None
_V17 = None
_TUPLE_ANCHOR = ' if type(value) in (tuple,list):return tuple(projection(x) for x in value)\n'
_IPV4_PROJECTION = (
    " ip=modules['mta_ip']\n"
    ' if type(value) in (ip.IpSnapshot,ip.AddressRecord,ip.RouteRecord,ip.RuleRecord):\n'
    '  return {key:projection(getattr(value,key)) for key in type(value)._fields}\n')


def _fixed(path, pin):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)):
        raise ValueError('source_shape')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('source_pin')
    return raw


def _projection_node(tree):
    matches = [node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == 'projection']
    if len(matches) != 1: raise ValueError('projection_definition')
    return matches[0]


def _derive_target(original):
    """Exactly one insertion; full reversal and whole-TARGET AST equality."""
    if type(original) is not str or original.count(_TUPLE_ANCHOR) != 1 or \
            _IPV4_PROJECTION in original:
        raise ValueError('projection_fragment')
    revised = original.replace(_TUPLE_ANCHOR, _IPV4_PROJECTION + _TUPLE_ANCHOR, 1)
    if revised.count(_IPV4_PROJECTION) != 1 or \
            revised.replace(_IPV4_PROJECTION, '', 1) != original:
        raise ValueError('projection_reverse')
    old_tree = ast.parse(original, feature_version=(3, 5))
    new_tree = ast.parse(revised, feature_version=(3, 5))
    old = _projection_node(old_tree); new = _projection_node(new_tree)
    anchor = ast.parse('def projection(value):\n' + _TUPLE_ANCHOR).body[0].body[0]
    indices = [i for i, node in enumerate(old.body) if ast.dump(node) == ast.dump(anchor)]
    if len(indices) != 1: raise ValueError('projection_anchor_ast')
    at = indices[0]
    insertion = ast.parse('def projection(value):\n' + _IPV4_PROJECTION,
        feature_version=(3, 5)).body[0].body
    if [ast.dump(node) for node in new.body[at:at + len(insertion)]] != \
            [ast.dump(node) for node in insertion]:
        raise ValueError('projection_insertion_ast')
    del new.body[at:at + len(insertion)]
    if ast.dump(new_tree) != ast.dump(old_tree): raise ValueError('target_ast_changed')
    return revised


def _definition(raw, name):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    matches = [node for node in ast.parse(text).body
        if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1: raise ValueError('profile_definition')
    node = matches[0]
    return ''.join(text.splitlines(True)[node.lineno - 1:node.end_lineno])


def _label_definition(profile, raw, name, changes):
    """Rebuild from frozen original bytes; permit only reviewed string labels."""
    original = _definition(raw, name); revised = original
    for before, after in changes:
        if revised.count(before) != 1 or after in revised:
            raise ValueError('profile_fragment')
        revised = revised.replace(before, after, 1)
    reverse = revised
    for before, after in reversed(changes): reverse = reverse.replace(after, before, 1)
    if reverse != original: raise ValueError('profile_reverse')
    old_tree = ast.parse(original, feature_version=(3, 5))
    new_tree = ast.parse(revised, feature_version=(3, 5))
    for node in ast.walk(new_tree):
        if isinstance(node, ast.Constant) and type(node.value) is str:
            for before, after in reversed(changes): node.value = node.value.replace(after, before)
    if ast.dump(new_tree) != ast.dump(old_tree): raise ValueError('profile_ast_changed')
    exec(compile(revised, '<v20-fixed-host-labels>', 'exec'), profile.__dict__)


def configured_profile():
    global _PROFILE, _V17
    if _PROFILE is not None: return _PROFILE
    raw = _fixed(V17, V17_SHA)
    previous = types.ModuleType('v20_fixed_v17'); previous.__file__ = str(V17)
    exec(raw, previous.__dict__)
    profile = previous.configured_profile()
    profile.TARGET = _derive_target(profile.TARGET)
    fixed_profile = _fixed(PROFILE, PROFILE_SHA)
    _label_definition(profile, fixed_profile, 'build_source', (
        ('client-v3-baseline-readonly-performance', 'client-readonly-ipv4-v20'),))
    _label_definition(profile, fixed_profile, 'execute', (
        ('P011_V3_BASELINE_READONLY_PERFORMANCE', 'P011_READONLY_IPV4_V20'),
        ('V3 first baseline READONLY timing diagnostic;', 'V20 readonly private IPv4 projection;')))
    profile.__file__ = str(Path(__file__).absolute())
    _V17 = previous; _PROFILE = profile
    return profile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly', action='store_true')
    parser.add_argument('--expected-driver-sha256')
    args = parser.parse_args(argv)
    if args.execute_readonly != (args.expected_driver_sha256 is not None):
        parser.error('Explicit readonly and reviewed SHA required together')
    try:
        profile = configured_profile()
        if args.execute_readonly:
            output = ROOT / 'logs' / ('MtaP011-ClientReadonlyIpv4V20-' +
                datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex())
            report = profile.execute(args.expected_driver_sha256, _output=output)
        else: report = profile.source_check()[0]
        print(json.dumps(report, indent=2))
        return 0 if report.get('diagnostic_complete', report.get('source_check_pass', False)) else 1
    except Exception:
        print(json.dumps({'diagnostic_complete': False, 'stage': 'transport_unknown',
            'send_available': False, 'receive_available': False, 'phone_tested': False}))
        return 1


if __name__ == '__main__': raise SystemExit(main())
