"""PC-only exclusive UI binding writer; no SOURCE, tests, old mains or device IO.

Copy one exact retained navigation observer into the frozen ordinary runner.
Change only six top-level Worker identity assignments. All business functions,
deadlines, source/FD gates and the original preflight/private/stage order remain
byte-identical. The generated report is preparation, not runtime acceptance.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/formal-receive-durable-ui-v1/'
SELF = PREFIX + 'generate_mechanical.py'
NEW_RUNNER = PREFIX + 'runtime/mta_formal_receive_session.py'
NEW_WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
REPORT = PREFIX + 'generation.json'
PINS = (
    ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_formal_receive_session.py',
     79254, '3fe23e4e9d9e1c9900985ee04153ce4b479ca1f2bc194458b91a702cd4f8258f'),
    ('candidate/formal-receive-filecenter-navigation-classification-v3/runtime/mta_formal_receive_session.py',
     88825, '421e8aa52f224e3a1f6d5ee9508af7bb2f49efc7d246a5bf59315b01e45e4ae3'),
    ('candidate/formal-receive-filecenter-navigation-classification-v3/runtime/ui_session.py',
     95430, '2d607a1b68ce640d0c981b76342b654a9190933ed65cc459813ffea41ef7e02a'),
    ('candidate/formal-receive-durable-state-v1/runtime/mta_formal_receive_session.py',
     79202, '38b7345454df94b1f5742d8c2f6a91a4cd8d0b1262909d4deacea2d48456008e'),
    ('candidate/formal-receive-durable-state-gui-v1/runtime/ui_assets.py',
     12798, '67e3d2d1bd7654cde6993d9746c8dd2cb3447676f0fb0f4bb2dec4a2ffb8d1bb'))
OBSERVER_START = b'    def original_receive_ui_cancelled_empty(self):\n'
OBSERVER_END = b'    def load_owner(self):\n'
SESSION = '559c72ccf8f8ff1b7fc83fb6'
SUFFIX = '-formal-receive-durable-ui-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-rx-durable-v1'
STATE_ALIAS = '/tmp/p011-mta-rx-durable-v1'


def need(condition, code):
    if condition is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def read_pin(source):
    path = BASE / source[0]
    need(path.resolve().is_relative_to(BASE.resolve()), 'source_scope')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == source[1:], 'source_identity:' + source[0])
    return raw


def json_raw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before = row['after' if inverse else 'before'].encode('utf-8')
        after = row['before' if inverse else 'after'].encode('utf-8')
        need(before and after and before != after and type(row['count']) is int and
             row['count'] > 0 and raw.count(before) == row['count'], 'replacement_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    nodes = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
             isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(nodes) == 1, 'literal_assignment:' + name)
    return ast.literal_eval(nodes[0].value)


def observer(raw):
    need(raw.count(OBSERVER_START) == raw.count(OBSERVER_END) == 1, 'observer_anchor')
    left, right = raw.index(OBSERVER_START), raw.index(OBSERVER_END)
    need(left < right and right - left == 9571, 'observer_bytes')
    block = raw[left:right]
    facts = dict(start_byte=left, end_byte_exclusive=right,
                 start_line=raw[:left].count(b'\n') + 1,
                 end_line_exclusive=raw[:right].count(b'\n') + 1,
                 bytes=len(block), sha256=digest(block))
    return raw[:left] + raw[right:], block, facts


def build():
    old_base, old_ui, old_worker, new_base, validator = tuple(read_pin(value) for value in PINS)
    stripped, block, old_range = observer(old_ui)
    need(stripped == old_base, 'old_ui_actual_ordinary_base')
    need(OBSERVER_START not in new_base and new_base.count(OBSERVER_END) == 1,
         'new_ordinary_observer_absent')
    need(literal(new_base, 'STATE_ROOT') == STATE_ROOT and
         literal(new_base, 'STATE_ALIAS') == STATE_ALIAS and
         literal(validator, 'SESSION') == SESSION, 'actual_core_gui_roots')
    runner_edits = [dict(name='unchanged_navigation_observer_insertion', count=1,
                         before=OBSERVER_END.decode('ascii'),
                         after=(block + OBSERVER_END).decode('ascii'))]
    new_ui = replay(new_base, runner_edits)
    need(replay(new_ui, runner_edits, True) == new_base, 'runner_inverse')
    new_stripped, new_block, new_range = observer(new_ui)
    need(new_stripped == new_base and new_block == block and len(new_ui) == 88773,
         'runner_exact_overlay')
    runner_pin = pin(NEW_RUNNER, new_ui)

    worker_edits = [
        dict(name='actual_navigation_runner_pin', count=1,
             before='RUNNER_PIN = ' + repr(PINS[1][1:]),
             after='RUNNER_PIN = ' + repr(runner_pin[1:])),
        dict(name='actual_gui20_validator_pin', count=1,
             before="VALIDATOR_PIN = (12642, 'a620878186a3005f36febf5487675c3031c8831fd91d5e8962660ad99466c4be')",
             after='VALIDATOR_PIN = ' + repr(PINS[4][1:])),
        dict(name='actual_gui20_session', count=1,
             before="SESSION = 'a87de5c1d0e0b90b35bb2a91'",
             after='SESSION = ' + repr(SESSION)),
        dict(name='independent_control_suffix', count=1,
             before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-classification-v3'",
             after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(SUFFIX)),
        dict(name='actual_state_physical_root', count=1,
             before="STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-profile-classification-clock-v1'",
             after='STATE_ROOT = ' + repr(STATE_ROOT)),
        dict(name='actual_state_alias', count=1,
             before="STATE_ALIAS = '/tmp/p011-mta-receive-profile-classification-clock-v1'",
             after='STATE_ALIAS = ' + repr(STATE_ALIAS))]
    new_worker = replay(old_worker, worker_edits)
    need(replay(new_worker, worker_edits, True) == old_worker, 'worker_inverse')
    worker_pin = pin(NEW_WORKER, new_worker)
    for name, value in (('RUNNER_PIN', runner_pin[1:]), ('VALIDATOR_PIN', PINS[4][1:]),
                        ('SESSION', SESSION), ('STATE_ROOT', STATE_ROOT), ('STATE_ALIAS', STATE_ALIAS)):
        need(literal(new_worker, name) == value, 'worker_literal:' + name)
    for path, raw in ((NEW_RUNNER, new_ui), (NEW_WORKER, new_worker)):
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
    for name in ('READY_SECONDS', 'SMOKE_DISPLAY_SECONDS', 'INTERACTIVE_SECONDS',
                 'EXIT_MARGIN_SECONDS', 'AUDIO_MAX', 'AUDIO_ACK_SECONDS', 'MONITOR_PIN',
                 'FILECENTER_PINS', 'STARTUP_BOOL_FIELDS', 'STARTUP_COUNT_FIELDS', 'TRIAL_BOOL_FIELDS'):
        need(literal(old_worker, name) == literal(new_worker, name), 'unchanged_worker_constant:' + name)
    stage_order = (b'        component.preflight()\n'
                   b"        need(component.result['private_assets_verified'], 'private_assets_required')\n"
                   b'        component.stage()\n')
    need(old_worker.count(stage_order) == new_worker.count(stage_order) == 1, 'original_stage_order')
    guards = dict(runtime_roles=75, ordinary_roles=35, private_roles=35, filecenter_sources=9,
                  filecenter_source_cap=131072, public_ui_fields=51,
                  ready_seconds=10, navigation_display_seconds=20, display_origin='launched',
                  owner_seconds=600, cleanup_seconds=60, guardian_margins=[68, 135],
                  original_preflight_privateassets_stage_retained=True,
                  business_logic_changed=False, resource_gates_changed=False,
                  frozen_core_changed=False, frozen_gui_changed=False,
                  tests_executed=False, source_check_executed=False, device_executed=False)
    generator_pin = pin(SELF, (BASE / SELF).read_bytes())
    spec = dict(schema='p011-formal-receive-durable-ui-v1-mechanical-delta',
                evidence='MECHANICAL_READBACK_NOT_SOURCE_CHECKED',
                sources=[list(value) for value in PINS], generator=list(generator_pin),
                observer=dict(source=list(PINS[1]), original_range=old_range, candidate_range=new_range,
                              insertion_anchor=OBSERVER_END.decode('ascii'), unchanged_bytes=True),
                entries=[dict(name='ui_runner', source=list(PINS[3]), candidate=list(runner_pin),
                              replacements=runner_edits),
                         dict(name='ui_worker', source=list(PINS[2]), candidate=list(worker_pin),
                              replacements=worker_edits)], guards=guards)
    outputs = {NEW_RUNNER: new_ui, NEW_WORKER: new_worker, DELTA: json_raw(spec)}
    need(len(outputs[DELTA]) <= 65536, 'delta_budget')
    report = dict(schema='p011-formal-receive-durable-ui-v1-generation',
                  status='MECHANICAL_GENERATED_NOT_SOURCE_CHECKED',
                  sources=[list(value) for value in PINS], generator=list(generator_pin),
                  outputs=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
                  guards=guards, observer_bytes=9571, observer_sha256=digest(block),
                  runner_inverse_verified=True, worker_inverse_verified=True,
                  source_checked=False, test_executed=False, device_executed=False,
                  phone_tested=False, file_transfer_tested=False, restoration_verified=False)
    outputs[REPORT] = json_raw(report)
    return outputs, report


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_mechanical_write_required')
    outputs, report = build()
    for path in outputs:
        target = BASE / path
        need(path.startswith(PREFIX) and target.resolve().is_relative_to((BASE / PREFIX).resolve()) and
             not target.exists(), 'fresh_output:' + path)
    for path, raw in outputs.items():
        target = BASE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'mechanical_write')
        need(target.read_bytes() == raw, 'mechanical_readback:' + path)
    for value in PINS:
        read_pin(value)
    print(json.dumps(dict(status=report['status'], observer_bytes=9571,
                         output_count=len(outputs), outputs=report['outputs']), sort_keys=True))


if __name__ == '__main__':
    main()
