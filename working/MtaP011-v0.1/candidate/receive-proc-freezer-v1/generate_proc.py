"""PC-only exact one-line Proc clone; default SOURCE-only, explicit fresh write.

Only stable_key's temporary comparison value masks Linux 4.14.174
PF_FREEZER_SKIP. Original flags/raw, all other bits, IO, identity checks,
deadlines, resource accounting and source line numbers remain unchanged.
No runtime role, historical checker/test, device or RF operation is executed.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-proc-freezer-v1/'
SELF = PREFIX + 'generate_proc.py'
TARGET = PREFIX + 'runtime/mta_client_proc.py'
DELTA = PREFIX + 'proc-exactsource-delta.json'
REPORT = PREFIX + 'proc-generation.json'
SOURCE = ('candidate/client-proc-deadline-v25/runtime/mta_client_proc.py', 39384,
          'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6')
BEFORE = '        return self.pid, self.start, self.comm, self.flags, self.ppid\n'
AFTER = '        return self.pid, self.start, self.comm, self.flags & ~0x40000000, self.ppid\n'
EDIT = dict(name='stable_key_masks_only_pf_freezer_skip', count=1,
            before=BEFORE, after=AFTER)
GUARDS = dict(mask=1073741824, other_flags_bits_preserved=31,
              original_flags_and_raw_preserved=True, stable_key_line=120,
              return_line=121, actor_pass_line=484, identity_failure_line=524,
              parse_stat_unchanged=True, pf_kthread_checks_unchanged=True,
              boot_exe_cmdline_tasks_directory_checks_unchanged=True,
              deadlines_and_resource_accounting_unchanged=True,
              original_source_unchanged=True, device_executed=False,
              tests_executed=False, admission=False, restoration_verified=False)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(relative, raw):
    return [relative, len(raw), digest(raw)]


def scoped(relative):
    path = BASE / relative
    need(not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()), 'source_scope')
    return path


def source():
    raw = scoped(SOURCE[0]).read_bytes()
    need((len(raw), digest(raw)) == SOURCE[1:], 'original_proc_pin')
    return raw


def build(raw):
    need(raw.count(BEFORE.encode('ascii')) == 1 and raw.count(AFTER.encode('ascii')) == 0,
         'unique_original_return')
    result = raw.replace(BEFORE.encode('ascii'), AFTER.encode('ascii'), 1)
    need(result.count(AFTER.encode('ascii')) == 1 and
         result.replace(AFTER.encode('ascii'), BEFORE.encode('ascii'), 1) == raw,
         'complete_proc_inverse')
    old_lines, new_lines = raw.splitlines(keepends=True), result.splitlines(keepends=True)
    need(len(old_lines) == len(new_lines) and old_lines[120] == BEFORE.encode('ascii') and
         new_lines[120] == AFTER.encode('ascii') and
         [index for index, pair in enumerate(zip(old_lines, new_lines)) if pair[0] != pair[1]] == [120],
         'one_return_line_only')
    old_tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    new_tree = ast.parse(result.decode('ascii'), feature_version=(3, 5))
    old_nodes = [(type(node).__name__, getattr(node, 'name', None), node.lineno, node.end_lineno)
                 for node in ast.walk(old_tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    new_nodes = [(type(node).__name__, getattr(node, 'name', None), node.lineno, node.end_lineno)
                 for node in ast.walk(new_tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    need(old_nodes == new_nodes, 'original_definition_lines')
    classes = [node for node in new_tree.body if isinstance(node, ast.ClassDef) and node.name == 'StatIdentity']
    need(len(classes) == 1 and classes[0].lineno == 112, 'stat_identity_original')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == 'stable_key']
    need(len(methods) == 1 and methods[0].lineno == 120 and len(methods[0].body) == 1 and
         isinstance(methods[0].body[0], ast.Return), 'stable_key_original_shape')
    expected = ast.parse('def stable_key(self):\n' + AFTER, feature_version=(3, 5)).body[0]
    need(ast.dump(methods[0], include_attributes=False) == ast.dump(expected, include_attributes=False),
         'exact_masked_return_ast')
    return result


def current_generator():
    return pin(SELF, scoped(SELF).read_bytes())


def generated_inputs():
    """Validate only already-created artifacts; never create or execute them."""
    original = source()
    actual = scoped(TARGET).read_bytes()
    need(actual == build(original), 'actual_proc_exact_delta')
    delta_raw, report_raw = scoped(DELTA).read_bytes(), scoped(REPORT).read_bytes()
    need(0 < len(delta_raw) <= 32768 and 0 < len(report_raw) <= 32768, 'metadata_bounds')
    delta, report = json.loads(delta_raw.decode('ascii')), json.loads(report_raw.decode('ascii'))
    generator = current_generator()
    expected_delta = dict(schema='p011-receive-proc-freezer-v1-proc-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
        source=list(SOURCE), candidate=pin(TARGET, actual), replacements=[EDIT], guards=GUARDS)
    need(delta == expected_delta, 'actual_proc_delta_metadata')
    expected_report = dict(schema='p011-receive-proc-freezer-v1-proc-generation',
        status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
        source=list(SOURCE), outputs=[pin(path, raw) for path, raw in
        sorted(((TARGET, actual), (DELTA, delta_raw)))], guards=GUARDS,
        host_checked=False, phone_tested=False)
    need(report == expected_report, 'actual_proc_generation_metadata')
    return {SOURCE[0]: original, SELF: scoped(SELF).read_bytes(), TARGET: actual,
            DELTA: delta_raw, REPORT: report_raw}


def source_facts():
    original = source()
    result = build(original)
    return dict(mode='SOURCE_ONLY', original=list(SOURCE),
                would_generate_bytes=len(result), candidate_written=False,
                future_candidate_pin_published=False, exact_delta=True,
                complete_inverse=True, original_line_numbers=True, guards=GUARDS)


def main():
    args = sys.argv[1:]
    if not args:
        print(json.dumps(source_facts(), sort_keys=True))
        return 0
    need(args == ['--write'], 'source_only_or_explicit_write')
    original = source()
    result = build(original)
    generator = current_generator()
    delta = dict(schema='p011-receive-proc-freezer-v1-proc-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
        source=list(SOURCE), candidate=pin(TARGET, result), replacements=[EDIT], guards=GUARDS)
    delta_raw = (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')
    outputs = {TARGET: result, DELTA: delta_raw}
    report = dict(schema='p011-receive-proc-freezer-v1-proc-generation',
        status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
        source=list(SOURCE), outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
        guards=GUARDS, host_checked=False, phone_tested=False)
    outputs[REPORT] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    root = (BASE / PREFIX).resolve()
    for relative in outputs:
        target = scoped(relative)
        need(relative.startswith(PREFIX) and target.resolve().is_relative_to(root) and
             not target.exists(), 'fresh_proc_output')
    for relative, raw in outputs.items():
        target = scoped(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'mechanical_short_write')
        need(target.read_bytes() == raw, 'mechanical_readback')
    need(source() == original, 'original_proc_after_write')
    generated_inputs()
    print(json.dumps(dict(status=report['status'],
        outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
        host_checked=False, device_tested=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
