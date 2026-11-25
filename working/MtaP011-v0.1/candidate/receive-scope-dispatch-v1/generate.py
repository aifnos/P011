"""PC-only Scope dispatch plan; --write exclusively creates two new outputs.

Only _StartupReadScope._originals' two existing zip scans change from
any(generator) to explicit for.  All inputs stay eager, ordered and once-read;
all predicates, failures, IO, clocks and deadlines are otherwise unchanged.
No Factory/Scope/Owner is imported or executed, and no device is contacted.
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
SELF = 'candidate/receive-scope-dispatch-v1/generate.py'
MOTHER = ('candidate/receive-owner-dispatch-graph-v1/runtime/mta_client_receive_factory.py',
          99257, '0103f047e9598767f9e9162cf8833f0420c171f7552c31ed28e107e6a91c6cb0')
TARGET = 'candidate/receive-scope-dispatch-v1/runtime/mta_client_receive_factory.py'
DELTA = 'candidate/receive-scope-dispatch-v1/exactsource-delta.json'
LIMIT = 2 * 1024 * 1024
BYTE_DELTA = 114
LINE_DELTA = 5
BEFORE = (
    b'                type(self._alias_owner_codes) is not tuple or len(self._alias_owner_codes) != 4 or\n'
    b'                any(current is not original or current.__code__ is not code for current, original, code in zip(\n'
    b'                    (self.owner_type._context, self.owner_type._now, self.owner_type._startup_readonly, self.owner_type.close),\n'
    b'                    self._alias_owner_methods, self._alias_owner_codes)) or\n'
    b'                any(current is not original or current.__code__ is not code for current, original, code in zip(\n'
    b'                    (_StartupReadScope.__init__, _StartupReadScope._originals, _StartupReadScope.check_active,\n'
    b'                     _StartupReadScope.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n'
    b'                    self._alias_functions, self._alias_codes)) or\n'
    b"                getattr(self._alias_clock, '__self__', None) is not self or\n"
    b"                getattr(self._alias_clock, '__func__', None) is not self._alias_functions[3]):\n"
    b"            _fail('startup_owner_changed')\n")
AFTER = (
    b'                type(self._alias_owner_codes) is not tuple or len(self._alias_owner_codes) != 4):\n'
    b"            _fail('startup_owner_changed')\n"
    b'        for current, original, code in zip(\n'
    b'                (self.owner_type._context, self.owner_type._now, self.owner_type._startup_readonly, self.owner_type.close),\n'
    b'                self._alias_owner_methods, self._alias_owner_codes):\n'
    b'            if current is not original or current.__code__ is not code:\n'
    b"                _fail('startup_owner_changed')\n"
    b'        for current, original, code in zip(\n'
    b'                (_StartupReadScope.__init__, _StartupReadScope._originals, _StartupReadScope.check_active,\n'
    b'                 _StartupReadScope.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n'
    b'                self._alias_functions, self._alias_codes):\n'
    b'            if current is not original or current.__code__ is not code:\n'
    b"                _fail('startup_owner_changed')\n"
    b"        if (getattr(self._alias_clock, '__self__', None) is not self or\n"
    b"                getattr(self._alias_clock, '__func__', None) is not self._alias_functions[3]):\n"
    b"            _fail('startup_owner_changed')\n")


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


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
    need(metadata(path.lstat()) == metadata(before) and len(raw) == before.st_size, 'source_changed')
    if pin is not None:
        need((len(raw), sha(raw)) == tuple(pin), 'source_pin')
    return raw


def scope_originals(tree):
    scopes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_StartupReadScope']
    need(len(scopes) == 1, 'scope_class_unique')
    methods = [node for node in scopes[0].body if isinstance(node, ast.FunctionDef) and node.name == '_originals']
    need(len(methods) == 1, 'scope_originals_unique')
    return methods[0]


def definitions(raw, tree):
    text = raw.decode('utf-8')
    return [(node.name, ast.get_source_segment(text, node)) for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name != '_originals']


def derive(raw):
    need(type(raw) is bytes and (len(raw), sha(raw)) == MOTHER[1:], 'mother_pin')
    need(b'\r' not in raw and raw.count(BEFORE) == 1 and raw.count(AFTER) == 0, 'literal_forward_unique')
    candidate = raw.replace(BEFORE, AFTER)
    need(candidate.count(AFTER) == 1 and candidate.replace(AFTER, BEFORE) == raw, 'complete_byte_inverse')
    old = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    new = ast.parse(candidate.decode('utf-8'), feature_version=(3, 5))
    old_method, new_method = scope_originals(old), scope_originals(new)
    scans = [node for node in ast.walk(old_method.body[0]) if isinstance(node, ast.GeneratorExp)]
    loops = [node for node in new_method.body[:4] if isinstance(node, ast.For)]
    need(len(scans) == len(loops) == 2 and
         sum(isinstance(node, ast.GeneratorExp) for node in ast.walk(old_method)) == 2 and
         sum(isinstance(node, ast.GeneratorExp) for node in ast.walk(new_method)) == 0 and
         sum(isinstance(node, ast.For) for node in ast.walk(old_method)) == 1 and
         sum(isinstance(node, ast.For) for node in ast.walk(new_method)) == 3, 'only_two_dispatch_scans_changed')
    for scan, loop in zip(scans, loops):
        need(len(scan.generators) == 1 and scan.generators[0].ifs == [] and
             ast.dump(scan.elt, include_attributes=False) == ast.dump(loop.body[0].test, include_attributes=False) and
             ast.dump(scan.generators[0].target, include_attributes=False) == ast.dump(loop.target, include_attributes=False) and
             ast.dump(scan.generators[0].iter, include_attributes=False) == ast.dump(loop.iter, include_attributes=False),
             'zip_predicates_order_and_eager_inputs_unchanged')
    inverse = ast.parse(candidate.replace(AFTER, BEFORE).decode('utf-8'), feature_version=(3, 5))
    need(ast.dump(inverse, include_attributes=True) == ast.dump(old, include_attributes=True), 'complete_ast_inverse')
    normalized = copy.deepcopy(new)
    scope_originals(normalized).body = copy.deepcopy(old_method.body)
    need(ast.dump(normalized, include_attributes=False) == ast.dump(old, include_attributes=False), 'one_method_ast_delta')
    need(definitions(raw, old) == definitions(candidate, new), 'other_definition_bytes_unchanged')
    need(len(candidate) - len(raw) == BYTE_DELTA and
         AFTER.count(b'\n') - BEFORE.count(b'\n') == LINE_DELTA and len(candidate) <= LIMIT, 'fixed_size_delta')
    return candidate


def delta_for(raw, candidate):
    return dict(schema='p011-receive-scope-dispatch-v1-exactsource-delta',
        origin=dict(path=MOTHER[0], bytes=MOTHER[1], sha256=MOTHER[2]),
        candidate=dict(path=TARGET, bytes=len(candidate), sha256=sha(candidate)),
        replacements=[dict(before=BEFORE.decode('ascii'), after=AFTER.decode('ascii'), count=1)],
        business_methods=['_StartupReadScope._originals'], business_delta_count=1,
        byte_delta=BYTE_DELTA, later_definition_line_delta=LINE_DELTA,
        owner_scan_rows=4, scope_scan_rows=6, same_order_and_eager_tuple_inputs=True,
        unchanged_predicates_and_clock_tail=True, failure_short_circuit_preserved=True,
        complete_byte_inverse=True, complete_ast_inverse=True, other_definition_bytes_unchanged=True,
        io_boundaries_changed=False, deadlines_changed=False, guards_removed=False,
        original_code_receipts_still_required=True, device_executed=False,
        rf_executed=False, measured_performance_claim=False)


def prepare(raw=None):
    raw = read_fixed(MOTHER[0], MOTHER[1:]) if raw is None else raw
    candidate = derive(raw)
    delta = (json.dumps(delta_for(raw, candidate), sort_keys=True, indent=2) + '\n').encode('utf-8')
    outputs = ({'path': TARGET, 'raw': candidate}, {'path': DELTA, 'raw': delta})
    facts = dict(schema='p011-receive-scope-dispatch-v1-source-plan', source_pin=MOTHER,
        candidate_pin=(TARGET, len(candidate), sha(candidate)), delta_pin=(DELTA, len(delta), sha(delta)),
        output_count=2, byte_delta=BYTE_DELTA, later_definition_line_delta=LINE_DELTA,
        business_delta_count=1, complete_byte_inverse=True, complete_ast_inverse=True,
        other_definition_bytes_unchanged=True, same_order_and_eager_tuple_inputs=True,
        io_boundaries_changed=False, deadlines_changed=False, guards_removed=False,
        device_executed=False, rf_executed=False, measured_performance_claim=False)
    return outputs, facts


def write_fresh(outputs):
    need(all(not (BASE / row['path']).exists() and not (BASE / row['path']).is_symlink()
             for row in outputs), 'output_exists')
    for row in outputs:
        path = BASE / row['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            need(handle.write(row['raw']) == len(row['raw']), 'output_short_write')
            handle.flush()
            os.fsync(handle.fileno())
        need(read_fixed(row['path'], (len(row['raw']), sha(row['raw']))) == row['raw'], 'output_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    mother, own = read_fixed(MOTHER[0], MOTHER[1:]), read_fixed(SELF)
    outputs, facts = prepare(mother)
    if args.write:
        write_fresh(outputs)
    else:
        facts['existing_outputs'] = []
        for row in outputs:
            path = BASE / row['path']
            present = path.exists() or path.is_symlink()
            if present:
                need(read_fixed(row['path'], (len(row['raw']), sha(row['raw']))) == row['raw'], 'existing_output_changed')
            facts['existing_outputs'].append(dict(path=row['path'], present=present, exact=True if present else None))
    need(read_fixed(MOTHER[0], MOTHER[1:]) == mother and read_fixed(SELF) == own, 'source_input_preserved')
    facts.update(generator_pin=(SELF, len(own), sha(own)), written=args.write, source_inputs_preserved=True)
    print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
