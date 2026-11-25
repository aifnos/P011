"""Explicit PC-only mechanical Worker clone for one atomic empty observation.

The original Runner/runtime75/GUI bytes and cached four-field guard do not
change. No candidate, test, device, project generator or runtime is executed.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-navigation-atomic-v1/'
SELF = PREFIX + 'generate.py'
WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
REPORT = PREFIX + 'generation.json'
SOURCE = ('candidate/receive-navigation-frame-v2/runtime/ui_session.py', 95351,
          '0c53b23051e5d79cdc392b2f89d3d21de2425028ff4f76292284a72f631cb4fe')
HELPER = '''def _receive_ui_empty_pair(component):
    """Original empty outcomes under original State then Trial RLocks only."""
    try:
        if type(_RETAINED) is not dict or _RETAINED.get('component') is not component:
            return False, False
        retained = _RETAINED.get('navigation_observer')
        originals = _RETAINED.get('navigation_empty_originals')
        if (type(retained) is not tuple or len(retained) != 3 or
                type(originals) is not tuple or len(originals) != 6):
            return False, False
        cls, method, code = retained
        original, owner, state, state_lock, trial, trial_lock = originals
        if (original is not component or type(component) is not cls or
                type(method) is not types.FunctionType or
                getattr(cls, 'original_receive_ui_cancelled_empty', None) is not method or
                method.__code__ is not code or method.__globals__.get('FixedSession') is not cls or
                component.owner is not owner or component.loader is not owner.loader):
            return False, False
        owner_module = component.owner_module
        service = component.loader.modules.get('mta_service')
        gate_module = component.loader.modules.get('mta_receive_trial')
        thread_module = sys.modules.get('_thread')
        if (type(owner_module) is not types.ModuleType or
                type(owner) is not owner_module.FixedStateServiceOwner or
                owner._startup_owner_type_original is not owner_module.FixedStateServiceOwner or
                owner._startup_namespace_original is not owner_module.__dict__ or
                owner_module.FixedStateServiceOwner.__init__.__globals__ is not owner_module.__dict__ or
                type(service) is not types.ModuleType or owner.service is not service or
                sys.modules.get('mta_service') is not service or type(state) is not service.State or
                owner.state is not state or owner._state_original is not state or
                type(gate_module) is not types.ModuleType or
                sys.modules.get('mta_receive_trial') is not gate_module or
                type(trial) is not gate_module.FixedReceiveTrial or
                owner.receive_trial is not trial or owner._receive_trial_original is not trial or
                trial.state is not state or state._receive_trial_original is not trial or
                type(thread_module) is not types.ModuleType or
                type(state_lock) is not thread_module.RLock or
                type(trial_lock) is not thread_module.RLock or state_lock is trial_lock or
                state.lock is not state_lock or
                trial._lock is not trial_lock or trial._lock_original is not trial_lock):
            return False, False
        with state_lock:
            with trial_lock:
                if (component.owner is not owner or component.loader is not owner.loader or
                        component.owner_module is not owner_module or
                        component.loader.modules.get('mta_service') is not service or
                        component.loader.modules.get('mta_receive_trial') is not gate_module or
                        sys.modules.get('mta_service') is not service or
                        sys.modules.get('mta_receive_trial') is not gate_module or
                        owner.state is not state or owner._state_original is not state or
                        owner.receive_trial is not trial or owner._receive_trial_original is not trial or
                        trial.state is not state or state._receive_trial_original is not trial or
                        state.lock is not state_lock or trial._lock is not trial_lock or
                        trial._lock_original is not trial_lock or
                        _RETAINED.get('navigation_empty_originals') is not originals or
                        _RETAINED.get('navigation_observer') is not retained or
                        getattr(cls, 'original_receive_ui_cancelled_empty', None) is not method or
                        method.__code__ is not code or method.__globals__.get('FixedSession') is not cls):
                    return False, False
                cancelled_empty = _receive_ui_cancelled_empty(component)
                navigation_idle = component.original_receive_ui_idle()
                return cancelled_empty is True, navigation_idle is True
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        return False, False


'''
EDITS = (
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-navigation-frame-v2'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-navigation-atomic-v1'\n"),
    dict(name='retain_after_successful_original_load_owner_same_line', count=1,
         before='        component.load_owner()\n',
         after="        component.load_owner(); _RETAINED.update(navigation_empty_originals=(component, component.owner, component.owner._state_original, component.owner._state_original.lock, component.owner._receive_trial_original, component.owner._receive_trial_original._lock_original)) if navigation_test else None\n"),
    dict(name='atomic_pair_preserves_three_lines_and_cached_four_guard', count=1,
         before='                cancelled_empty = _receive_ui_cancelled_empty(component)\n'
                "                navigation_cancelled_diagnostic = component.__dict__.get('_navigation_cancelled_diagnostic')\n"
                '                navigation_idle = component.original_receive_ui_idle()\n',
         after='                cancelled_empty, navigation_idle = _receive_ui_empty_pair(component)\n'
               "                navigation_cancelled_diagnostic = component.__dict__.get('_navigation_cancelled_diagnostic')\n"
               '                # Both original outcomes were observed under the same locks.\n'),
    dict(name='helper_after_run_fixed_before_source_only_main', count=1,
         before="if __name__ == '__main__':\n",
         after=HELPER + "if __name__ == '__main__':\n"),
)
GUARDS = dict(original_predicates_reused=True, cached_four_guards_unchanged=True,
              run_fixed_line=1246, navigation_failure_line=1560, runner_observer_line=817,
              state_then_trial_original_rlocks=True, original_locks_once_retained=True,
              runtime75_modified=False, runner_modified=False, gui_rebuilt=False,
              gui_staged=False, public_fields=51, startup_seconds=10,
              service_seconds=600, cleanup_seconds=60, new_clock_calls=0,
              new_probe_calls=0, device_executed=False, tests_executed=False)


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


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == row['count'], 'mechanical_count:' + row['name'])
        raw = raw.replace(before, after, row['count'])
    return raw


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return {node.name: (node.lineno, node.end_lineno,
                       b''.join(lines[node.lineno - 1:node.end_lineno]))
            for node in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))}


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    old = source()
    new = replay(old)
    need(replay(new, True) == old, 'worker_complete_inverse')
    old_defs, new_defs = definitions(old), definitions(new)
    need(set(new_defs) == set(old_defs) | {'_receive_ui_empty_pair'}, 'only_one_added_helper')
    need(all(new_defs[name] == value for name, value in old_defs.items() if name != 'run_fixed'),
         'unaffected_definitions_unchanged')
    need(old_defs['run_fixed'][:2] == new_defs['run_fixed'][:2] and
         new_defs['run_fixed'][0] == 1246 and
         b"                     'navigation_receive_activity')\n" in new.splitlines(keepends=True)[1559:1560],
         'original_failure_lines_preserved')
    generator = pin(SELF, (BASE / SELF).read_bytes())
    delta = dict(schema='p011-receive-navigation-atomic-v1-worker-delta',
                 evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                 source=list(SOURCE), candidate=pin(WORKER, new),
                 replacements=list(EDITS), guards=GUARDS)
    outputs = {WORKER: new,
               DELTA: (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')}
    report = dict(schema='p011-receive-navigation-atomic-v1-generation',
                  status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=generator,
                  source=list(SOURCE), outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
                  guards=GUARDS, host_checked=False, phone_tested=False)
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
    source()
    print(json.dumps(dict(status=report['status'],
                         outputs=[pin(path, raw) for path, raw in sorted(outputs.items())]), sort_keys=True))


if __name__ == '__main__':
    main()
