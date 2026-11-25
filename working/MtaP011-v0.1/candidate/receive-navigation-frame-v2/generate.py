"""Explicit PC-only CONTROL clone; writes only a new Worker and exact delta.

No imports or execution of project definitions, tests, generators or device
entry points. The whole Worker inverse and definition/line identity are checked.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-navigation-frame-v2/'
SELF = PREFIX + 'generate.py'
WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
SOURCE = ('candidate/receive-startup-workload-v1/runtime/ui_session.py', 95351,
          '8a90425b76303ae28fbd44760bd1f6623980fbf616f25bcfd67953603d275773')
EDITS = (
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-navigation-frame-v2'\n"),)
GUARDS = dict(business_bytes_unchanged=True, worker_line_numbers_unchanged=True,
              runtime75_modified=False, gui_rebuilt=False, gui_staged=False,
              public_fields=51, startup_seconds=10, service_seconds=600,
              cleanup_seconds=60, device_executed=False, tests_executed=False)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return [path, len(raw), digest(raw)]


def source():
    path = BASE / SOURCE[0]
    need(path.resolve().is_relative_to(BASE.resolve()) and not path.is_symlink(), 'source_scope')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == SOURCE[1:], 'source_pin')
    return raw


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return [(node.name, node.lineno, node.end_lineno,
             b''.join(lines[node.lineno - 1:node.end_lineno]))
            for node in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))]


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    old = source()
    before, after = (EDITS[0][key].encode('ascii') for key in ('before', 'after'))
    need(old.count(before) == 1, 'control_count')
    new = old.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         definitions(new) == definitions(old) and
         len(new.splitlines()) == len(old.splitlines()), 'worker_complete_inverse')
    delta = dict(schema='p011-receive-navigation-frame-v2-worker-delta',
                 evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED',
                 generator=pin(SELF, (BASE / SELF).read_bytes()), source=list(SOURCE),
                 candidate=pin(WORKER, new), replacements=list(EDITS), guards=GUARDS)
    outputs = {WORKER: new,
               DELTA: (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')}
    root = (BASE / PREFIX).resolve()
    for relative in outputs:
        target = BASE / relative
        need(relative.startswith(PREFIX) and target.resolve().is_relative_to(root) and
             not target.exists(), 'fresh_output')
    for relative, raw in outputs.items():
        target = BASE / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'mechanical_short_write')
        need(target.read_bytes() == raw, 'mechanical_readback')
    source()
    print(json.dumps(dict(status='MECHANICAL_GENERATED_NOT_HOST_CHECKED',
                         outputs=[pin(path, raw) for path, raw in sorted(outputs.items())]), sort_keys=True))


if __name__ == '__main__':
    main()
