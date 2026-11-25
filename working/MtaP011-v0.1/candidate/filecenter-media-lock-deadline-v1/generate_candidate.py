"""Pure, pinned media-lock recipe; only --write creates exclusive HOST outputs.

This is a PC authoring recipe, not a device/Owner/test authority.  It never
imports a runtime candidate, starts a server, executes an old main, or runs ADB.
Root freezes this file before its one generation.  Existing output bytes must
all agree before any absent output is created.  No receive graph is changed.
"""
import ast
import hashlib
import json
import sys
from pathlib import Path


SOURCE_PINS = (
    ('candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py',
     26088, '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f'),
    ('candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py',
     33630, '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba'),
)
DESTINATION = 'candidate/filecenter-media-lock-deadline-v1'
CHANGED_METHODS = (
    '_FileCenterHandler.dispatch', '_FileCenterHandler.media',
    '_Companion.open_file', '_Companion.media_row', '_Companion.audio_source_fd',
)
ADDED_METHODS = ('_MediaLock.__init__', '_MediaLock.__enter__', '_MediaLock.__exit__')

HELPER = b'''class _MediaLock:
    """Wait only within the retained parent/caller cap, without renewing it."""
    def __init__(self, companion, lock, deadline=None):
        parent_until = companion.until
        if type(parent_until) is not float or not math.isfinite(parent_until):
            raise ValueError('original_finite_cap_required')
        if deadline is not None and (type(deadline) is not float or not math.isfinite(deadline)):
            raise ValueError('filecenter_finite_media_deadline_required')
        self.companion, self.lock = companion, lock
        self.deadline = parent_until if deadline is None else min(parent_until, deadline)

    def __enter__(self):
        while True:
            self.companion.check()
            remaining = self.deadline - time.monotonic()
            if remaining <= 0: raise ValueError('filecenter_media_lock_deadline')
            if self.lock.acquire(timeout=min(0.05, remaining)):
                try:
                    self.companion.check()
                    if time.monotonic() >= self.deadline:
                        raise ValueError('filecenter_media_lock_deadline')
                except BaseException:
                    self.lock.release()
                    raise
                return self

    def __exit__(self, error_type, error, traceback):
        self.lock.release()
        return False


'''

REPLACEMENTS = (
    (b'\ndef _owner_binding(owner, module):\n',
     b'\n' + HELPER + b'def _owner_binding(owner, module):\n'),
    (b"self.server.companion.open_file(query.get('path', ''))",
     b"self.server.companion.open_file(query.get('path', ''), deadline=self.deadline)"),
    (b"        row = self.server.companion.media_row(query)\n        with row['lock']:\n",
     b"        row = self.server.companion.media_row(query, deadline=self.deadline)\n"
     b"        with _MediaLock(self.server.companion, row['lock'], self.deadline):\n"),
    (b'    def open_file(self, path):\n', b'    def open_file(self, path, deadline=None):\n'),
    (b'        with self.media_lock:\n            for row in self.media:\n',
     b'        with _MediaLock(self, self.media_lock, deadline):\n            for row in self.media:\n'),
    (b'    def media_row(self, query):\n', b'    def media_row(self, query, deadline=None):\n'),
    (b"        with self.media_lock:\n            rows = [row for row in self.media if row['cap'] == query['cap']]\n",
     b"        with _MediaLock(self, self.media_lock, deadline):\n"
     b"            rows = [row for row in self.media if row['cap'] == query['cap']]\n"),
    (b"        with self.media_lock:\n            rows = [row for row in self.media if row['valid'] and row['kind']=='audio' and\n",
     b"        with _MediaLock(self, self.media_lock):\n"
     b"            rows = [row for row in self.media if row['valid'] and row['kind']=='audio' and\n"),
)


def need(value, code):
    if not value: raise ValueError(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def definition_bytes(raw):
    lines = raw.splitlines(keepends=True)
    tree = ast.parse(raw.decode('utf-8'))
    result = {}
    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = '.'.join(prefix + (child.name,))
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    need(name not in result, 'duplicate_definition')
                    result[name] = b''.join(lines[child.lineno-1:child.end_lineno])
                walk(child, prefix + (child.name,))
            else:
                walk(child, prefix)
    walk(tree, ())
    return tree, result


def derive(raw):
    need(b'\r' not in raw, 'original_lf_required')
    value = raw
    for before, after in REPLACEMENTS:
        need(value.count(before) == 1, 'exact_forward')
        need(after not in value, 'new_anchor_already_present')
        value = value.replace(before, after, 1)
    inverse = value
    for before, after in reversed(REPLACEMENTS):
        need(inverse.count(after) == 1, 'exact_inverse')
        inverse = inverse.replace(after, before, 1)
    need(inverse == raw, 'complete_byte_inverse')
    old_tree, old_defs = definition_bytes(raw)
    new_tree, new_defs = definition_bytes(value)
    need(set(new_defs) == set(old_defs) | set(ADDED_METHODS), 'exact_definition_inventory')
    changed = {name for name in old_defs if old_defs[name] != new_defs[name]}
    need(changed == set(CHANGED_METHODS), 'only_media_methods_changed')
    helper_tree = ast.parse(HELPER.decode('ascii'))
    helpers = [node for node in new_tree.body if isinstance(node, ast.ClassDef) and node.name == '_MediaLock']
    need(len(helpers) == 1 and ast.dump(helpers[0], include_attributes=False) ==
         ast.dump(helper_tree.body[0], include_attributes=False), 'exact_helper_ast')
    need(ast.dump(ast.parse(inverse.decode('utf-8')), include_attributes=False) ==
         ast.dump(old_tree, include_attributes=False), 'complete_ast_inverse')
    need(b'with self.media_lock:' not in value and b"with row['lock']:" not in value,
         'no_unbounded_media_context')
    need(new_defs['_Companion.close'] == old_defs['_Companion.close'] and
         new_defs['_Companion.closed'] == old_defs['_Companion.closed'] and
         new_defs['_Companion.check'] == old_defs['_Companion.check'] and
         new_defs['create'] == old_defs['create'], 'original_guards_close_binding')
    return value


def prepare():
    """Read pinned sources and assemble bytes only; never create output files."""
    repo = Path(__file__).resolve().parents[2]
    outputs, inputs, variants = {}, {}, []
    for path, size, sha in SOURCE_PINS:
        raw = (repo / path).read_bytes()
        need((len(raw), digest(raw)) == (size, sha), 'original_source_pin')
        inputs[path] = raw
        side = path.split('/')[-2]
        target = DESTINATION + '/' + side + '/mta_filecenter_companion.py'
        candidate = derive(raw)
        outputs[target] = candidate
        origin_pin = dict(path=path, bytes=size, sha256=sha)
        candidate_pin = dict(path=target, bytes=len(candidate), sha256=digest(candidate))
        delta = dict(
            schema='filecenter-media-lock-deadline-v1-exactsource-delta',
            side=side, origin=origin_pin, candidate=candidate_pin,
            replacements=[dict(before=before.decode('ascii'), after=after.decode('ascii'), count=1)
                          for before, after in REPLACEMENTS],
            changed_methods=list(CHANGED_METHODS), added_methods=list(ADDED_METHODS),
            complete_byte_inverse=True, complete_ast_inverse=True,
            all_other_definition_bytes_unchanged=True, close_method_bytes_unchanged=True,
            original_guard_bytes_unchanged=True, parent_original_until_unchanged=True,
            handler_absolute_deadline_forwarded=True, lock_wait_slice_seconds=0.05,
            new_deadline_created=False, already_acquired_lock_released_on_error=True,
            unowned_lock_released=False, fd_identity_io_http_status_unchanged=True,
            blocking_file_io_preemption_verified=False,
            host_test_executed=False, device_verified=False, graph_changed=False,
            owner_authority_granted=False, radio_operation_requested=False)
        outputs[DESTINATION + '/' + side + '/exactsource-delta.json'] = (
            json.dumps(delta, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
        variants.append(dict(side=side, origin=origin_pin, candidate=candidate_pin,
                             growth_bytes=len(candidate)-len(raw)))
    facts = dict(
        schema='filecenter-media-lock-deadline-v1-generation', variants=variants,
        output_count=len(outputs), replacements_per_variant=len(REPLACEMENTS),
        complete_byte_inverse=True, complete_ast_inverse=True,
        all_other_definition_bytes_unchanged=True,
        handler_parent_cap_only=True, nonhandler_uses_retained_companion_until=True,
        no_owner_fixture_identity_forged=True, close_policy_unchanged=True,
        no_runtime_import=True, no_test_or_device_execution=True,
        original_75_role_graph_unchanged=True, source_graph_integrated=False,
        real_owner_device_verified=False, blocking_file_io_preemption_verified=False)
    return outputs, facts, inputs


def write_outputs(outputs):
    repo = Path(__file__).resolve().parents[2]
    destination = repo / DESTINATION
    planned = []
    for name, value in sorted(outputs.items()):
        path = repo / name
        need(destination in path.parents and not path.is_symlink(), 'confined_output')
        ancestor = path.parent
        while ancestor != repo:
            need(not ancestor.is_symlink(), 'output_parent_symlink')
            ancestor = ancestor.parent
        if path.exists(): need(path.is_file() and path.read_bytes() == value, 'existing_output_differs')
        planned.append((path, value))
    for path, value in planned:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open('xb') as stream: stream.write(value)
        need(path.read_bytes() == value, 'output_readback')


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_write_required')
    outputs, facts, inputs = prepare()
    write_outputs(outputs)
    print(json.dumps(facts, sort_keys=True, ensure_ascii=True))


if __name__ == '__main__': main()
