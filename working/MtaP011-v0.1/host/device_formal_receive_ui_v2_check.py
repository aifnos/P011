"""Thin Receive UI driver-v2: fixed v1 definitions, corrected artifact order only.

Default SOURCE; TEST CMD explicitly selects the same original UI smoke. The v1
HOST, ten staged assets,75 production roles, worker/guardian/profile and all
budgets stay frozen. No old main, graph, suite, builder or runner is executed by
the pure order audit. Raw v1 HOST enters the inherited private input/readback.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_ui_v2_check.py'
CMD = 'TEST_MTA_FORMAL_RECEIVE_UI_V2.cmd'
ORIGINAL = ('host/device_formal_receive_ui_v1_check.py', 24136,
            'f72c802ab8fbec8cc1e0b228ed8c779dd69752b9fa279ad1b966558c4d095857')
OLD_ORDER = 'ordinary + private_rows + graph.HELPERS + (graph.WPA, graph.MONITOR)'
NEW_ORDER = 'ordinary + graph.HELPERS + private_rows + (graph.WPA, graph.MONITOR)'
PRIVATE_FORM = "tuple(('runtime35/' + name, size, sha) for name, size, sha in PRIVATE_PINS)"


def need(value, code):
    if value is not True: raise ValueError(code)


def shape(node): return ast.dump(node, include_attributes=False)


def expression(source): return ast.parse(source, mode='eval').body


def v2_payload_order(payload, runner_raw):
    """Actual runner's five pin domains, no runner import/exec or platform IO."""
    wanted = ('ROLE_PINS', 'HELPER_PINS', 'PRIVATE_PINS',
              'PRIVATE_PAYLOAD_PINS', 'WPA_PIN', 'MONITOR_PIN')
    found = {}
    for node in ast.parse(runner_raw, feature_version=(3, 5)).body:
        if not isinstance(node, ast.Assign): continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in wanted:
                need(target.id not in found, 'payload_order_assignment')
                found[target.id] = node.value
    need(set(found) == set(wanted) and
         shape(found['PRIVATE_PAYLOAD_PINS']) == shape(expression(PRIVATE_FORM)),
         'payload_order_private_form')
    ordinary = ast.literal_eval(found['ROLE_PINS'])
    helpers = ast.literal_eval(found['HELPER_PINS'])
    private = ast.literal_eval(found['PRIVATE_PINS'])
    wpa, monitor = (ast.literal_eval(found[name]) for name in ('WPA_PIN', 'MONITOR_PIN'))
    need(type(ordinary) is type(helpers) is type(private) is tuple and
         len(ordinary) == 35 and len(helpers) == 3 and len(private) == 35,
         'payload_order_domains')
    expected = ordinary + helpers + tuple(('runtime35/' + name, size, sha)
                                          for name, size, sha in private) + (wpa, monitor)
    actual = tuple((name, size, sha) for name, path, size, sha in payload)
    need(actual == expected and len(actual) == 75, 'payload_role_order')
    return dict(verified=True, ordinary_count=35, helper_count=3, private_count=35,
                total_count=75, runner_executed=False, private_form='fixed_runtime35_prefix')


def patched_main(raw):
    """Three changes: order, original-input seed, driver revision/pure audit."""
    old_tree = ast.parse(raw, feature_version=(3, 5))
    matches = [row for row in old_tree.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(matches) == 1, 'driver_main_count')
    original = matches[0]; new = copy.deepcopy(original)
    orders = []; seeds = []; reports = []; runner_reads = []
    for at, row in enumerate(new.body):
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name):
            name = row.targets[0].id
            if name == 'inputs': seeds.append(row)
            if name == 'report': reports.append(row)
        if isinstance(row, ast.Try):
            for index, item in enumerate(row.body):
                if (isinstance(item, ast.Assign) and len(item.targets) == 1 and
                        isinstance(item.targets[0], ast.Name) and item.targets[0].id == 'payload'):
                    orders.append(item)
                if isinstance(item, ast.Expr) and shape(item.value) == shape(expression('read(graph.RUNNER)')):
                    runner_reads.append((row.body, index))
    need(len(orders) == len(seeds) == len(reports) == len(runner_reads) == 1,
         'driver_patch_count')
    order, seed, report = orders[0], seeds[0], reports[0]
    need(shape(order.value) == shape(expression(OLD_ORDER)) and
         isinstance(seed.value, ast.Dict) and not seed.value.keys and not seed.value.values and
         isinstance(report.value, ast.Call) and shape(report.value.func) == shape(expression('dict')) and
         not any(row.arg in ('driver_revision', 'payload_role_order_verified') for row in report.value.keywords),
         'driver_patch_original')
    old_order, old_seed, old_keywords = copy.deepcopy(order.value), copy.deepcopy(seed.value), copy.deepcopy(report.value.keywords)
    order.value = expression(NEW_ORDER)
    seed.value = expression('{V2_ORIGINAL[0]: V2_ORIGINAL_RAW}')
    report.value.keywords.extend((ast.keyword(arg='driver_revision', value=ast.Constant(value=2)),
        ast.keyword(arg='payload_role_order_verified', value=ast.Constant(value=False))))
    body, at = runner_reads[0]
    additions = ast.parse("report['payload_order_audit'] = v2_payload_order(payload, inputs[graph.RUNNER[0]])\n"
                          "report['payload_role_order_verified'] = True\n").body
    body[at + 1:at + 1] = additions
    # Undo precisely these edits; every retained original main node must match.
    audit = copy.deepcopy(new)
    audit_orders = [row for item in audit.body if isinstance(item, ast.Try) for row in item.body
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name)
        and row.targets[0].id == 'payload']
    audit_orders[0].value = old_order
    for row in audit.body:
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name):
            if row.targets[0].id == 'inputs': row.value = old_seed
            if row.targets[0].id == 'report': row.value.keywords = old_keywords
        if isinstance(row, ast.Try):
            row.body = [item for item in row.body if all(shape(item) != shape(added) for added in additions)]
    need(shape(audit) == shape(original), 'driver_inverse_main')
    return ast.fix_missing_locations(ast.Module(body=[new], type_ignores=[]))


def main():
    raw = (BASE / ORIGINAL[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == ORIGINAL[1:], 'driver_original_pin')
    module = types.ModuleType('fixed_receive_ui_v2_original_definitions')
    module.__file__ = str(BASE / ORIGINAL[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    need(module.BASE == BASE, 'driver_original_base')
    module.SELF, module.CMDS = SELF, (CMD,)
    module.V2_ORIGINAL, module.V2_ORIGINAL_RAW = ORIGINAL, raw
    module.v2_payload_order = v2_payload_order
    exec(compile(patched_main(raw), str(BASE / SELF), 'exec'), module.__dict__)
    return module.main()


if __name__ == '__main__': raise SystemExit(main())
