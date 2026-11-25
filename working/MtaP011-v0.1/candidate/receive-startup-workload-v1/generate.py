"""Explicit PC-only one-suffix Worker clone; no device or test action.

All Worker function/class bytes, line numbers and frozen window Runner remain
unchanged. The passive workload function is a separate after-return carrier
fragment, never inserted into Worker/Factory/Loader or runtime75.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-startup-workload-v1/'
SELF = PREFIX + 'generate.py'
WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
REPORT = PREFIX + 'generation.json'
SOURCE = ('candidate/receive-window-clock-ui-v1/runtime/ui_session.py', 95350,
          'ed08e5fa40f44170e9d5e7c64c3944e23ab91e3eb17472e4cb8e7f4a5fa9d997')
EDITS = (
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'\n"),)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return [path, len(raw), digest(raw)]


def read_source():
    path = BASE / SOURCE[0]
    need(path.resolve().is_relative_to(BASE.resolve()) and not path.is_symlink(), 'source_scope')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == SOURCE[1:], 'source_pin')
    return raw


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == 1, 'suffix_count')
        raw = raw.replace(before, after, 1)
    return raw


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return [(node.name, b''.join(lines[node.lineno - 1:node.end_lineno]))
            for node in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))]


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    old = read_source()
    new = replay(old)
    need(replay(new, True) == old and definitions(new) == definitions(old) and
         len(new.splitlines()) == len(old.splitlines()), 'worker_complete_inverse')
    generator = pin(SELF, (BASE / SELF).read_bytes())
    guards = dict(business_bytes_unchanged=True, runtime75_modified=False,
                  gui_rebuilt=False, gui_staged=False, public_fields=51,
                  startup_seconds=10, service_seconds=600, cleanup_seconds=60,
                  device_executed=False, tests_executed=False)
    delta = dict(schema='p011-receive-startup-workload-v1-worker-delta',
                 evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED',
                 generator=generator, source=list(SOURCE), candidate=pin(WORKER, new),
                 replacements=list(EDITS), guards=guards)
    outputs = {WORKER: new,
               DELTA: (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')}
    report = dict(schema='p011-receive-startup-workload-v1-generation',
                  status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                  source=list(SOURCE), outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
                  guards=guards, host_checked=False, phone_tested=False)
    outputs[REPORT] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
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
    read_source()
    print(json.dumps(dict(status=report['status'], outputs=report['outputs']), sort_keys=True))


if __name__ == '__main__':
    main()
