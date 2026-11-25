"""PC-only exact Owner dispatch delta; default plans, --write is EXCL only.

This does not import an Owner, execute a context, or touch a device.  The sole
business delta removes a generator from the existing nine-item method scan.
Every predicate, its order and every original IO/deadline boundary are kept.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
import stat
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/receive-owner-dispatch-v1/generate.py'
MOTHER = ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_service_owner.py',
          107026, 'a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7')
TARGET = 'candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py'
DELTA = 'candidate/receive-owner-dispatch-v1/exactsource-delta.json'
LIMIT = 2 * 1024 * 1024
BEFORE = (
    b'                type(methods) is not tuple or len(methods) != 9 or\n'
    b'                any(type(value) is not types.FunctionType or getattr(type(self), name) is not value or\n'
    b'                    value.__globals__ is not self._startup_namespace_original or value.__code__ is not code\n'
    b'                    for name, value, code in methods) or\n'
    b'                self.filecenter_ticket is not self._filecenter_ticket_original):\n'
    b"            _fail('filecenter_original_changed')\n")
AFTER = (
    b'                type(methods) is not tuple or len(methods) != 9):\n'
    b"            _fail('filecenter_original_changed')\n"
    b'        for name, value, code in methods:\n'
    b'            if (type(value) is not types.FunctionType or getattr(type(self), name) is not value or\n'
    b'                    value.__globals__ is not self._startup_namespace_original or value.__code__ is not code):\n'
    b"                _fail('filecenter_original_changed')\n"
    b'        if self.filecenter_ticket is not self._filecenter_ticket_original:\n'
    b"            _fail('filecenter_original_changed')\n")


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    # Windows may synthesize executable bits; the fixed content pin is exact.
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


def read_fixed(relative, pin=None):
    path = BASE / relative
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and
         before.st_nlink == 1 and 0 < before.st_size <= LIMIT, 'source_identity')
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        need(opened == metadata(before), 'source_open_identity')
        raw = handle.read(LIMIT + 1)
        need(metadata(os.fstat(handle.fileno())) == opened, 'source_fstat_changed')
    need(metadata(path.lstat()) == metadata(before) and len(raw) == before.st_size,
         'source_changed')
    if pin is not None:
        need((len(raw), sha(raw)) == tuple(pin), 'source_pin')
    return raw


def owner_context(tree):
    owners = [n for n in tree.body if isinstance(n, ast.ClassDef) and
              n.name == 'FixedStateServiceOwner']
    need(len(owners) == 1, 'owner_class_unique')
    contexts = [n for n in owners[0].body if isinstance(n, ast.FunctionDef) and
                n.name == '_context']
    need(len(contexts) == 1, 'owner_context_unique')
    return contexts[0]


def definitions(raw, tree):
    text = raw.decode('utf-8')
    return [(n.name, ast.get_source_segment(text, n)) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            n.name != '_context']


def derive(raw):
    need(type(raw) is bytes and (len(raw), sha(raw)) == MOTHER[1:], 'mother_pin')
    need(b'\r' not in raw and raw.count(BEFORE) == 1 and raw.count(AFTER) == 0,
         'literal_forward_unique')
    candidate = raw.replace(BEFORE, AFTER)
    need(candidate.count(AFTER) == 1 and candidate.replace(AFTER, BEFORE) == raw,
         'complete_byte_inverse')
    old = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    new = ast.parse(candidate.decode('utf-8'), feature_version=(3, 5))
    old_context, new_context = owner_context(old), owner_context(new)
    need(sum(isinstance(n, ast.GeneratorExp) for n in ast.walk(old_context)) == 1 and
         sum(isinstance(n, ast.For) for n in ast.walk(old_context)) == 0 and
         sum(isinstance(n, ast.GeneratorExp) for n in ast.walk(new_context)) == 0 and
         sum(isinstance(n, ast.For) for n in ast.walk(new_context)) == 1,
         'only_dispatch_form_changed')
    inverse = ast.parse(candidate.replace(AFTER, BEFORE).decode('utf-8'),
                        feature_version=(3, 5))
    need(ast.dump(inverse, include_attributes=True) ==
         ast.dump(old, include_attributes=True), 'complete_ast_inverse')
    normalized = copy.deepcopy(new)
    owner_context(normalized).body = copy.deepcopy(old_context.body)
    need(ast.dump(normalized, include_attributes=False) ==
         ast.dump(old, include_attributes=False), 'one_method_ast_delta')
    need(definitions(raw, old) == definitions(candidate, new),
         'other_definition_bytes_unchanged')
    need(len(candidate) - len(raw) == 78, 'fixed_byte_delta')
    return candidate


def delta_for(raw, candidate):
    return dict(schema='p011-receive-owner-dispatch-v1-exactsource-delta',
        origin=dict(path=MOTHER[0], bytes=MOTHER[1], sha256=MOTHER[2]),
        candidate=dict(path=TARGET, bytes=len(candidate), sha256=sha(candidate)),
        replacements=[dict(before=BEFORE.decode('ascii'), after=AFTER.decode('ascii'), count=1)],
        business_methods=['FixedStateServiceOwner._context'], business_delta_count=1,
        byte_delta=78, nine_checks_same_order=True, failure_short_circuit_preserved=True,
        complete_byte_inverse=True, complete_ast_inverse=True,
        other_definition_bytes_unchanged=True, later_definition_line_delta=2,
        io_boundaries_changed=False, deadlines_changed=False, guards_removed=False,
        original_method_code_receipts_still_required=True,
        device_executed=False, rf_executed=False, measured_performance_claim=False)


def prepare(raw=None):
    raw = read_fixed(MOTHER[0], MOTHER[1:]) if raw is None else raw
    candidate = derive(raw)
    delta = (json.dumps(delta_for(raw, candidate), sort_keys=True, indent=2) + '\n').encode('utf-8')
    outputs = ({'path': TARGET, 'raw': candidate}, {'path': DELTA, 'raw': delta})
    facts = dict(schema='p011-receive-owner-dispatch-v1-source-plan',
        source_pin=MOTHER, candidate_pin=(TARGET, len(candidate), sha(candidate)),
        delta_pin=(DELTA, len(delta), sha(delta)), output_count=2, byte_delta=78,
        complete_byte_inverse=True, complete_ast_inverse=True,
        other_definition_bytes_unchanged=True, later_definition_line_delta=2,
        business_delta_count=1, device_executed=False, rf_executed=False,
        io_boundaries_changed=False, deadlines_changed=False, guards_removed=False,
        measured_performance_claim=False)
    return outputs, facts


def write_fresh(outputs):
    need(all(not (BASE / row['path']).exists() and not (BASE / row['path']).is_symlink()
             for row in outputs), 'output_exists')
    for row in outputs:
        path = BASE / row['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            written = handle.write(row['raw'])
            need(written == len(row['raw']), 'output_short_write')
            handle.flush()
            os.fsync(handle.fileno())
        need(read_fixed(row['path'], (len(row['raw']), sha(row['raw']))) == row['raw'],
             'output_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    mother = read_fixed(MOTHER[0], MOTHER[1:])
    own = read_fixed(SELF)
    outputs, facts = prepare(mother)
    if args.write:
        write_fresh(outputs)
    else:
        facts['existing_outputs'] = []
        for row in outputs:
            path = BASE / row['path']
            present = path.exists() or path.is_symlink()
            if present:
                need(read_fixed(row['path'], (len(row['raw']), sha(row['raw']))) == row['raw'],
                     'existing_output_changed')
            facts['existing_outputs'].append(dict(path=row['path'], present=present,
                                                  exact=True if present else None))
    need(read_fixed(MOTHER[0], MOTHER[1:]) == mother and read_fixed(SELF) == own,
         'source_input_preserved')
    facts.update(generator_pin=(SELF, len(own), sha(own)), written=args.write,
                 source_inputs_preserved=True)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
