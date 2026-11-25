"""Isolated v17 readonly first-source-failure notes; default SOURCE only.

No new device query, write, RF, restore, lock or admission entry. The original
19-source LOADER and public/close/pending predicates remain the frozen v6 ones.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import textwrap
import types

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
V6 = BASE / 'host/client_readparts_v6_readonly_p011.py'
V6_SHA = 'dc876207d674e950c888e7f40bd8b3dce88949e720a40fa17d0a70c5fb4a5c39'
NOTES = BASE / 'candidate/client-readonly-diagnostic-v17/status_source_notes.py'
NOTES_SHA = '7a77e35788c9294fd38591a7797139ddf77d0cda1dfd65d6a9fdf8008711e334'
STATUS_SHA = '4f0fa75132c8c81427f1d593fdc415b01657b061cd9d1dbcbcde789b52daf742'
_PROFILE = None
_INJECTION = None
_PROJECTION = "   record['source_first_failures']=tuple(_v17_project(files) for files in source._files)\n"
_ANCHOR = 'def timed_collector(p,unused_original_budget):\n'


def _fixed(path, pin):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)): raise ValueError('source_shape')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('source_pin')
    return raw


def _source_method(raw):
    """One exact source-method insertion, reversible AST; no runtime import."""
    if hashlib.sha256(raw).hexdigest() != STATUS_SHA: raise ValueError('status_pin')
    text = raw.decode('utf-8').replace('\r\n', '\n')
    owner = next(n for n in ast.parse(text).body if isinstance(n, ast.ClassDef) and n.name == 'LinuxStatusSource')
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'read_source')
    original = textwrap.dedent(''.join(text.splitlines(True)[method.lineno - 1:method.end_lineno]))
    if not original.endswith('\n'): original += '\n'
    before = '    except BaseException as caught: error = caught\n'
    after = "    except BaseException as caught:\n        _v17_record(files, caught, 'source_before_finally', None, None)\n        error = caught\n"
    if original.count(before) != 1: raise ValueError('source_fragment')
    revised = original.replace(before, after, 1).replace('def read_source(', 'def _v17_read_source(', 1)
    old_node = ast.parse(original).body[0]
    new_node = ast.parse(revised, feature_version=(3, 5)).body[0]
    new_node.name = 'read_source'
    handlers = [h for n in ast.walk(new_node) if isinstance(n, ast.Try) for h in n.handlers
        if h.name == 'caught' and isinstance(h.type, ast.Name) and h.type.id == 'BaseException']
    if len(handlers) != 1: raise ValueError('source_handler')
    note = ast.parse("_v17_record(files, caught, 'source_before_finally', None, None)").body[0]
    if ast.dump(handlers[0].body[0]) != ast.dump(note): raise ValueError('source_note')
    del handlers[0].body[0]
    if ast.dump(new_node) != ast.dump(old_node): raise ValueError('source_ast_changed')
    if revised.replace('def _v17_read_source(', 'def read_source(', 1).replace(after, before, 1) != original:
        raise ValueError('source_reverse')
    return revised


def _replace_definition(profile, raw, name, changes):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
    definition = ''.join(text.splitlines(True)[node.lineno - 1:node.end_lineno])
    for before, after in changes:
        if definition.count(before) != 1: raise ValueError('profile_fragment')
        definition = definition.replace(before, after, 1)
    exec(compile(definition, '<v17-fixed-host-labels>', 'exec'), profile.__dict__)


def configured_profile():
    global _PROFILE, _INJECTION
    if _PROFILE is not None: return _PROFILE
    raw = _fixed(V6, V6_SHA)
    module = types.ModuleType('v17_fixed_v6'); module.__file__ = str(V6)
    exec(raw, module.__dict__)
    profile = module.configured_profile()
    notes = _fixed(NOTES, NOTES_SHA).decode('utf-8')
    ast.parse(notes, feature_version=(3, 5))
    method = _source_method(_fixed(BASE / 'runtime/mta_client_wpa_status.py', STATUS_SHA))
    literal = '(\n' + '\n'.join(repr(method[i:i + 1000]) for i in range(0, len(method), 1000)) + ')'
    _INJECTION = notes + "\n_v17_install(modules['mta_client_wpa_status'], " + literal + ')\n'
    before = "   record['source_files']=tuple(tuple(ticket(r,files._io) for r in files._tickets) for files in source._files)\n"
    if profile.TARGET.count(_ANCHOR) != 1 or profile.TARGET.count(before) != 1: raise ValueError('target_fragment')
    profile.TARGET = profile.TARGET.replace(_ANCHOR, _INJECTION + _ANCHOR, 1).replace(before, _PROJECTION + before, 1)
    fixed_profile = _fixed(module.PROFILE, module.PROFILE_SHA)
    _replace_definition(profile, fixed_profile, 'build_source', (
        ("'client-v3-baseline-readonly-performance'", "'client-readonly-diagnostic-v17'"),))
    _replace_definition(profile, fixed_profile, 'execute', (
        ("'P011_V3_BASELINE_READONLY_PERFORMANCE'", "'P011_READONLY_DIAGNOSTIC_V17'"),
        ('V3 first baseline READONLY timing diagnostic;', 'V17 readonly anonymous first-source-failure notes;')))
    profile.__file__ = str(Path(__file__).absolute())
    _PROFILE = profile
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
            output = ROOT / 'logs' / ('MtaP011-ClientReadonlyDiagnosticV17-' +
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
