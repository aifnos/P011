"""PC-only exclusive mechanical writer for the finite-window predicate.

No test, RF, process, device or complete FixedSession is executed here. Each
candidate is an independent copy of a pinned runner. Only window_current's
two duration expressions change. The second edit also keeps strict increasing
deadlines, so NaN, infinity and unrepresentable positive spans stay rejected.
No clock read, tolerance, renewal, constructor or deadline check is changed.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-window-clock-v1/'
SELF = PREFIX + 'generate.py'
DELTA = PREFIX + 'exactsource-delta.json'
REPORT = PREFIX + 'generation.json'
SOURCES = (
    ('ordinary',
     'candidate/formal-receive-durable-state-v1/runtime/mta_formal_receive_session.py',
     79202, '38b7345454df94b1f5742d8c2f6a91a4cd8d0b1262909d4deacea2d48456008e',
     PREFIX + 'runtime/mta_formal_receive_session.py'),
    ('navigation',
     'candidate/formal-receive-durable-ui-v1/runtime/mta_formal_receive_session.py',
     88773, 'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3',
     PREFIX + 'runtime/mta_formal_receive_navigation_session.py'))
EDITS = (
    dict(name='duration_matches_original_construction', count=1,
         before="                self.until - self.window_started_at == (\n"
                "                    600.0 if self.profile == 'receive-interactive-v1' else 60.0) and\n",
         after="                self.until == self.window_started_at + (\n"
               "                    600.0 if self.profile == 'receive-interactive-v1' else 60.0) and\n"),
    dict(name='cleanup_matches_original_construction_and_strict_positive_spans', count=1,
         before='                self.cleanup_until - self.until == 60.0)\n',
         after='                self.cleanup_until == self.until + 60.0 and\n'
               '                self.window_started_at < self.until < self.cleanup_until)\n'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def read_pin(source):
    _, relative, size, sha, _ = source
    path = BASE / relative
    need(path.resolve().is_relative_to(BASE.resolve()), 'source_scope')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == (size, sha), 'source_identity:' + relative)
    return raw


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == row['count'], 'edit_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


def function(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and
               node.name == 'FixedSession']
    need(len(classes) == 1, 'fixed_class')
    nodes = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and
             node.name == name]
    need(len(nodes) == 1 and not nodes[0].decorator_list, 'fixed_function:' + name)
    node = nodes[0]
    lines = raw.splitlines(keepends=True)
    left = sum(len(line) for line in lines[:node.lineno - 1])
    right = sum(len(line) for line in lines[:node.end_lineno])
    return node, raw[left:right], left, right


def build():
    outputs, entries = {}, []
    for source in SOURCES:
        role, relative, _, _, target = source
        old = read_pin(source)
        new = replay(old)
        need(replay(new, True) == old, 'full_inverse:' + role)
        old_node, old_function, old_left, old_right = function(old, 'window_current')
        new_node, new_function, new_left, new_right = function(new, 'window_current')
        need(replay(old_function) == new_function and
             old[:old_left] == new[:new_left] and old[old_right:] == new[new_right:],
             'only_window_current_changed:' + role)
        old_tree = ast.parse(old.decode('utf-8'), feature_version=(3, 5))
        new_tree = ast.parse(new.decode('utf-8'), feature_version=(3, 5))
        old_class = next(node for node in old_tree.body if isinstance(node, ast.ClassDef) and
                         node.name == 'FixedSession')
        new_class = next(node for node in new_tree.body if isinstance(node, ast.ClassDef) and
                         node.name == 'FixedSession')
        old_class.body = [node for node in old_class.body if node is not old_node]
        # Nodes come from distinct parses; filter by the single proven name.
        old_class.body = [node for node in old_class.body if not
                          (isinstance(node, ast.FunctionDef) and node.name == 'window_current')]
        new_class.body = [node for node in new_class.body if not
                          (isinstance(node, ast.FunctionDef) and node.name == 'window_current')]
        need(ast.dump(old_tree, include_attributes=False) ==
             ast.dump(new_tree, include_attributes=False), 'other_ast_unchanged:' + role)
        for name in ('__init__', 'check'):
            need(function(old, name)[1] == function(new, name)[1],
                 'constructor_deadline_byte_unchanged:' + role + ':' + name)
        outputs[target] = new
        entries.append(dict(role=role, source=[relative, len(old), digest(old)],
                            candidate=list(pin(target, new)), replacements=list(EDITS),
                            function=dict(name='FixedSession.window_current',
                                          source_line=old_node.lineno,
                                          candidate_line=new_node.lineno,
                                          source_sha256=digest(old_function),
                                          candidate_sha256=digest(new_function)),
                            full_forward_inverse=True,
                            outside_function_byte_identical=True,
                            all_other_ast_identical=True,
                            constructor_and_deadline_byte_identical=True))
    generator = list(pin(SELF, (BASE / SELF).read_bytes()))
    guards = dict(identity_guards_unchanged=True, strict_positive_spans=True,
                  actual_clock_reads_added=0, epsilon_added=False,
                  renewal_added=False, deadline_check_changed=False,
                  diagnostic_seconds=60, interactive_seconds=600, cleanup_seconds=60,
                  complete_fixed_session_constructed=False, device_executed=False,
                  actual_device_window_values_collected=False)
    spec = dict(schema='p011-receive-window-clock-v1-mechanical-delta',
                evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                entries=entries, guards=guards)
    outputs[DELTA] = (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode('ascii')
    report = dict(schema='p011-receive-window-clock-v1-generation',
                  status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                  sources=[[row[1], row[2], row[3]] for row in SOURCES],
                  outputs=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
                  guards=guards, host_checked=False, tests_executed=False,
                  device_executed=False, phone_tested=False,
                  actual_device_failure_reproduced=False)
    outputs[REPORT] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    return outputs, report


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    outputs, report = build()
    prefix = (BASE / PREFIX).resolve()
    for relative in outputs:
        target = BASE / relative
        need(relative.startswith(PREFIX) and target.resolve().is_relative_to(prefix) and
             not target.exists(), 'fresh_output:' + relative)
    for relative, raw in outputs.items():
        target = BASE / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'mechanical_short_write')
        need(target.read_bytes() == raw, 'mechanical_readback:' + relative)
    for source in SOURCES:
        read_pin(source)
    print(json.dumps(dict(status=report['status'], outputs=report['outputs']), sort_keys=True))


if __name__ == '__main__':
    main()
