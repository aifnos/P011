"""Pure PC finite recipe; default SOURCE, explicit --write creates one new file.

No device, child, old entry/test, graph, phone or lifecycle invocation. The
frozen mother's main marker stays unchanged and is never called by this recipe.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
MOTHER = ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
          '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657')
OUTPUT = ('candidate/receive-handoff-terminal-v1/runtime/handoff_terminal.py', 15049,
          'c77db43cb42d60f624b96bacb92e5a8c03b943faf82921059ab4d04b15085c97')
REMOVE = b'        trace.install()\n'
RETURN = b'        return phone.run_fixed(runner, artifacts)'
GUARD = (b"        if sys.gettrace() is not None or getattr(threading, '_trace_hook', object()) is not None:\n"
         b"            trace.unknown_failure('existing_trace')\n"
         b"            raise ValueError('existing_trace')\n")
OLD_PUBLIC = b"return dict(schema='receive-handoff-trace-v1', thread_trace_installed=self.installed,"
NEW_PUBLIC = (b"return dict(schema='receive-handoff-terminal-v1', exception_events_observed=False,\n"
              b'                    thread_trace_installed=self.installed,')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def named(body, kind, name):
    rows = [node for node in body if isinstance(node, kind) and node.name == name]
    need(len(rows) == 1, 'ast_named')
    return rows[0]


def ast_inverse(mother, candidate):
    original = ast.parse(mother.decode('ascii'), feature_version=(3, 5))
    inverse = ast.parse(candidate.decode('ascii'), feature_version=(3, 5))
    old_run = named(original.body, ast.FunctionDef, 'run_fixed')
    new_run = named(inverse.body, ast.FunctionDef, 'run_fixed')
    old_try = [node for node in old_run.body if isinstance(node, ast.Try)]
    new_try = [node for node in new_run.body if isinstance(node, ast.Try)]
    need(len(old_try) == len(new_try) == 1 and len(old_try[0].body) == 2 and
         len(new_try[0].body) == 2 and isinstance(new_try[0].body[0], ast.If) and
         isinstance(new_try[0].body[1], ast.Return), 'run_ast')
    need(ast.dump(old_try[0].body[0], include_attributes=False) ==
         ast.dump(ast.parse('trace.install()').body[0], include_attributes=False), 'install_ast')
    old_owner = named(original.body, ast.ClassDef, 'TraceOwner')
    new_owner = named(inverse.body, ast.ClassDef, 'TraceOwner')
    old_install = named(old_owner.body, ast.FunctionDef, 'install')
    guard = ast.parse(GUARD.decode('ascii').strip()).body[0]
    # Strip only the bound receiver name for the original first-if AST check.
    expected_guard = ast.parse(ast.get_source_segment(mother.decode('ascii'), old_install.body[0])).body[0]
    guard_text = GUARD.decode('ascii').replace('trace.unknown_failure', 'self.unknown_failure')
    guard_normalized = ast.parse('\n'.join(line[8:] for line in guard_text.splitlines())).body[0]
    need(ast.dump(guard_normalized, include_attributes=False) ==
         ast.dump(expected_guard, include_attributes=False), 'original_hook_guard_ast')
    need(ast.dump(new_try[0].body[0], include_attributes=False) ==
         ast.dump(guard, include_attributes=False), 'candidate_hook_guard_ast')
    new_try[0].body[0] = old_try[0].body[0]
    old_public = named(old_owner.body, ast.FunctionDef, 'public')
    new_public = named(new_owner.body, ast.FunctionDef, 'public')
    need(len(old_public.body) == len(new_public.body) == 1 and
         isinstance(new_public.body[0], ast.Return) and
         isinstance(new_public.body[0].value, ast.Call), 'public_ast')
    keywords = new_public.body[0].value.keywords
    need(tuple(row.arg for row in keywords[:2]) == ('schema', 'exception_events_observed') and
         ast.literal_eval(keywords[0].value) == 'receive-handoff-terminal-v1' and
         ast.literal_eval(keywords[1].value) is False, 'public_fields_ast')
    del keywords[1]
    keywords[0].value = old_public.body[0].value.keywords[0].value
    need(ast.dump(inverse, include_attributes=False) == ast.dump(original, include_attributes=False),
         'full_ast_inverse')
    return True


def make_source(raw):
    need((len(raw), digest(raw)) == MOTHER[1:], 'mother_pin')
    need(raw.count(REMOVE) == raw.count(OLD_PUBLIC) == raw.count(RETURN) == 1, 'byte_anchors')
    candidate = raw.replace(REMOVE, GUARD, 1).replace(OLD_PUBLIC, NEW_PUBLIC, 1)
    need(candidate.count(NEW_PUBLIC) == candidate.count(RETURN) == candidate.count(GUARD) == 1,
         'byte_inverse_anchors')
    inverse = candidate.replace(NEW_PUBLIC, OLD_PUBLIC, 1).replace(GUARD, REMOVE, 1)
    need(inverse == raw, 'full_byte_inverse')
    ast_inverse(raw, candidate)
    need((len(candidate), digest(candidate)) == OUTPUT[1:], 'candidate_pin')
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    raw = (BASE / MOTHER[0]).read_bytes()
    target = make_source(raw)
    path = BASE / OUTPUT[0]
    if args.write:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as handle:
            need(handle.write(target) == len(target), 'short_write')
        need(path.read_bytes() == target, 'output_readback')
    need((BASE / MOTHER[0]).read_bytes() == raw, 'mother_changed')
    print(json.dumps(dict(mode='write' if args.write else 'source', output=str(path),
        written=args.write, bytes=len(target), sha256=digest(target),
        full_byte_inverse=True, full_ast_inverse=True, mother_preserved=True,
        old_main_called=False, device_invoked=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
