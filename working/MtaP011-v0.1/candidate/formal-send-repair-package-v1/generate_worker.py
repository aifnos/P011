"""PC-only sender repair Worker pin closure; default dry, explicit EXCL write.

Derive only eight top-level assignments in the preserved UI-v7 Worker. No
Worker, Owner, validator, guardian, device, RF, test or previous main runs.
The separate graph/UI generators must already have published their new files.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
ORIGIN = ('candidate/formal-send-filecenter-ui-v7/runtime/ui_session.py',
          46415, 'bbbaf091f20715531e045d1b7b1a281bc78d569f5bac6089da1b105d2282dbe4')
GRAPH = 'candidate/formal-send-filecenter-deploy-v6/assets/ordinary-source-manifest.json'
UI = 'candidate/formal-send-picker-package-v1/runtime/'
DEST = 'candidate/formal-send-repair-package-v1/runtime/ui_session.py'
DELTA = 'candidate/formal-send-repair-package-v1/exactsource-delta.json'
SESSION = 'c69296a193ff43ce8e5b901d'
SUFFIX = '-formal-send-picker-package-v1'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def take(path, inputs, pin=None):
    file = BASE / path
    need(file.is_file() and not file.is_symlink(), 'source_file')
    before = file.stat()
    raw = file.read_bytes()
    after = file.stat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in keys) ==
         tuple(getattr(after, key) for key in keys), 'source_changed')
    if pin is not None:
        need((len(raw), digest(raw)) == tuple(pin), 'input_pin')
    if path in inputs:
        need(inputs[path] == raw, 'source_changed')
    inputs[path] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw, feature_version=(3, 5))
    rows = [node for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'assignment_identity')
    return ast.literal_eval(rows[0].value)


def swap(raw, name, expression):
    tree = ast.parse(raw, feature_version=(3, 5))
    rows = [node for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'assignment_identity')
    lines = raw.splitlines(keepends=True)
    old = b''.join(lines[rows[0].lineno - 1:rows[0].end_lineno])
    new = (name + ' = ' + expression + '\n').encode('ascii')
    need(raw.count(old) == 1, 'assignment_count')
    derived = raw.replace(old, new, 1)
    ast.parse(derived, feature_version=(3, 5))
    return derived, dict(name=name, before=old.decode('ascii'), after=new.decode('ascii'), count=1)


def derive(inputs):
    origin = take(ORIGIN[0], inputs, ORIGIN[1:])
    catalog = json.loads(take(GRAPH, inputs))
    outer_rows = [row for row in catalog['startup_sources'] if row['module'] == 'formal_send_session']
    need(len(outer_rows) == 1 and catalog['source_count'] == 32 and
         catalog['physical_ordinary_root'] ==
         '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6/runtime', 'graph_identity')
    row = outer_rows[0]
    need(row['source'] == 'candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_session.py',
         'outer_identity')
    outer = take(row['source'], inputs, (row['bytes'], row['sha256']))
    guardian = take(UI + 'ui_guardian.py', inputs)
    validator = take(UI + 'ui_assets.py', inputs)
    need(literal(guardian, 'SESSION') == literal(validator, 'SESSION') == SESSION, 'ui_session')
    need(literal(outer, 'ROOT') == '/tmp/p011-mta-formal-send-filecenter-deploy-v6' and
         literal(outer, 'PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6',
         'outer_roots')
    control = [node for node in ast.parse(guardian).body if isinstance(node, ast.Assign) and
               any(isinstance(target, ast.Name) and target.id == 'CONTROL_NAME' for target in node.targets)]
    need(len(control) == 1 and ast.dump(control[0].value, include_attributes=False) ==
         ast.dump(ast.parse("'p011-mta-ui-session-' + SESSION + " + repr(SUFFIX), mode='eval').body,
                  include_attributes=False), 'guardian_control')
    desired = (
        ('SENDER_PIN', repr((len(outer), digest(outer)))),
        ('GUARDIAN_PIN', repr((len(guardian), digest(guardian)))),
        ('ASSETS_PIN', repr((len(validator), digest(validator)))),
        ('SENDER_ROOT', repr('/tmp/p011-mta-formal-send-filecenter-deploy-v6')),
        ('SENDER_PHYSICAL_ROOT', repr('/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6')),
        ('SESSION', repr(SESSION)),
        ('CONTROL_NAME', "'p011-mta-ui-session-' + SESSION + " + repr(SUFFIX)),
        ('SENDER_ASSET_SEAL', '(SESSION, ASSETS, ' + repr(literal(validator, 'MANIFEST_PIN')) + ')'),
    )
    current = origin
    replacements = []
    for name, expression in desired:
        current, row = swap(current, name, expression)
        replacements.append(row)
    restored = current
    for row in reversed(replacements):
        after, before = row['after'].encode('ascii'), row['before'].encode('ascii')
        need(restored.count(after) == 1, 'inverse_count')
        restored = restored.replace(after, before, 1)
    need(restored == origin, 'full_byte_inverse')
    left, right = ast.parse(origin, feature_version=(3, 5)), ast.parse(current, feature_version=(3, 5))
    names = {row[0] for row in desired}
    shape = lambda tree: [ast.dump(node, include_attributes=False) for node in tree.body
        if not (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names
            for target in node.targets))]
    need(shape(left) == shape(right), 'all_other_ast_unchanged')
    need(all((BASE / path).read_bytes() == raw for path, raw in inputs.items()), 'source_preserved')
    delta = dict(schema='p011-formal-send-repair-worker-v1-source',
        origin=list(ORIGIN), candidate=[DEST, len(current), digest(current)],
        replacements=replacements, byte_inverse=True, other_ast_unchanged=True,
        source_inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()],
        device=False, rf=False, phone=False, runtime_definitions_invoked=False)
    return current, (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'output_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    inputs = {}
    worker, delta = derive(inputs)
    if args.write:
        need(all(not (BASE / path).exists() for path in (DEST, DELTA)), 'exclusive_output_conflict')
        write_new(BASE / DEST, worker)
        write_new(BASE / DELTA, delta)
        need(all((BASE / path).read_bytes() == raw for path, raw in inputs.items()), 'source_preserved')
    print(json.dumps(dict(write_requested=args.write, worker_bytes=len(worker),
        worker_sha256=digest(worker), delta_sha256=digest(delta), source_count=len(inputs),
        assignments_changed=8, byte_inverse=True, other_ast_unchanged=True,
        device=False, rf=False, phone=False), sort_keys=True))


if __name__ == '__main__':
    main()
