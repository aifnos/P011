"""Exclusive PC-only mechanical Worker clone; no test, device or generator call.

Only RUNNER_PIN and CONTROL_NAME's fixed suffix change. All function/class
bytes and the actual GUI20/session/validator/core75 references remain exact.
The separate new runner is already frozen, not copied or generated here.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-window-clock-ui-v1/'
SELF = PREFIX + 'generate.py'
WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
REPORT = PREFIX + 'generation.json'
SOURCE = ('candidate/formal-receive-durable-ui-v1/runtime/ui_session.py', 95352,
          '7690e2c87f8438c3422986d180381858e7e47588ee60c725c9eb8f73dd628972')
RUNNER = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py',
          88850, '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
EDITS = (
    dict(name='fixed_runner_pin', count=1,
         before="RUNNER_PIN = (88773, 'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')\n",
         after="RUNNER_PIN = (88850, '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')\n"),
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-durable-ui-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'\n"))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return [path, len(raw), digest(raw)]


def read_pin(identity):
    relative, size, sha = identity
    path = BASE / relative
    need(path.resolve().is_relative_to(BASE.resolve()) and not path.is_symlink(), 'source_scope')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == (size, sha), 'source_identity')
    return raw


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == 1, 'worker_edit_count')
        raw = raw.replace(before, after, 1)
    return raw


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return [(node.name, b''.join(lines[node.lineno - 1:node.end_lineno]))
            for node in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))]


def build():
    old, runner = read_pin(SOURCE), read_pin(RUNNER)
    new = replay(old)
    need(replay(new, True) == old and definitions(old) == definitions(new), 'worker_exact_inverse')
    need(len(old.splitlines()) == len(new.splitlines()), 'worker_line_identity')
    generator = pin(SELF, (BASE / SELF).read_bytes())
    guards = dict(business_bytes_unchanged=True, gui_rebuilt=False, gui_staged=False,
                  runtime75_modified=False, public_fields=51, ready_seconds=10,
                  navigation_seconds=20, service_seconds=600, cleanup_seconds=60,
                  device_executed=False, tests_executed=False)
    spec = dict(schema='p011-receive-window-clock-ui-v1-worker-delta',
                evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                source=list(SOURCE), runner=list(RUNNER), candidate=pin(WORKER, new),
                replacements=list(EDITS), guards=guards)
    outputs = {WORKER: new,
               DELTA: (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode('ascii')}
    report = dict(schema='p011-receive-window-clock-ui-v1-generation',
                  status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                  sources=[list(SOURCE), list(RUNNER)],
                  outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
                  guards=guards, host_checked=False, phone_tested=False)
    outputs[REPORT] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    return outputs, report


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    outputs, report = build()
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
    read_pin(SOURCE); read_pin(RUNNER)
    print(json.dumps(dict(status=report['status'], outputs=report['outputs']), sort_keys=True))


if __name__ == '__main__':
    main()
