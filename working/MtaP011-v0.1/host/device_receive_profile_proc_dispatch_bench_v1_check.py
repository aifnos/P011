"""One inner Startup-guard CPU model benchmark; SOURCE by default.

The fixed measured Owner benchmark carrier supplies only the original read,
stock, transport, alarm30/HOST45 and artifact envelope. No old main or model is
run. New actual Factory sources supply only one inner guard's AST statements.
This cannot certify whole-profile speed, Startup completion or phone transfer.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_profile_proc_dispatch_bench_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROFILE_PROC_DISPATCH_BENCH_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROFILE_PROC_DISPATCH_BENCH_V1.cmd')
CARRIER = ('host/device_receive_owner_dispatch_bench_v1_check.py', 17325,
           '0221e95920035d118eda2637ee7e9ad0c166355346eaa03caf4f2010553ee0eb')
MAKER = ('host/receive_profile_proc_dispatch_bench_v1_target.py', 19079,
         '07edf1519a8ba6387419b21c8fab22353516c8b5ebe40e240ec1d729cb15c69e')
PROFILE_PINS = (
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py',
     99675, '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5'),
    ('candidate/receive-profile-proc-dispatch-v1/runtime/mta_client_receive_factory.py',
     99717, '3349e76e6da45d4948edde640e44829bb1eeb554156b91c686f2a6b655422b47'))
EXTRAS = (
    CARRIER,
    ('candidate/receive-profile-proc-dispatch-v1/generate_seed.py', 13116,
     '6aff0915c1df41eff9f81503062b4da254b3c489f0650e217b0d3c34729da605'),
    ('candidate/receive-profile-proc-dispatch-v1/exactsource-delta.json', 2921,
     '071dd1f19d35c81df736631a3bfaaa695b28d74f441f68cc866fa3b00a32001a'))
README = (b'Default SOURCE; explicit --check-device measures the real inner Startup guard AST only.\n'
    b'Two Factory sources have one 42-byte ordered dispatch delta; all native IO/clock/cache are unchanged.\n'
    b'Guard statements execute on synthetic fields and independent ordinary types, never native authority.\n'
    b'Four ABBA groups, sixteen blocks of8192 calls, warmup128 each; real monotonic and process CPU.\n'
    b'Alarm30 before exact stdin read, HOST45, source48000/line256/output65536 caps remain.\n'
    b'Original stock probes before and finally after; raw dual streams and exits remain private.\n'
    b'No actual _live_profile, clock/IO, Scope/Owner lifecycle, graph, Stage, UI, RF, credential or phone.\n'
    b'PASS is model/source/finite stock evidence, not whole-profile improvement, startup or interoperability.\n'
    b'Private snapshots and ZIP readback precede the public result commit.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def derive(raw):
    need((len(raw), hashlib.sha256(raw).hexdigest()) == CARRIER[1:], 'fixed_bench_carrier')
    need(type(MAKER) is tuple and len(MAKER) == 3, 'new_model_maker_not_sealed')
    original_tree = ast.parse(raw.decode('ascii'))
    current, changes = raw, []

    def change(before, after, count=1):
        nonlocal current
        before, after = before.encode('ascii'), after.encode('ascii')
        need(before != after and current.count(before) == count and not current.count(after),
             'bench_finite_forward')
        current = current.replace(before, after)
        changes.append((before, after, count))

    def constant(name, value):
        rows = [node for node in original_tree.body if isinstance(node, ast.Assign) and
                len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        need(len(rows) == 1, 'bench_single_constant')
        before = ast.get_source_segment(raw.decode('ascii'), rows[0])
        change(before, name + ' = ' + repr(value))

    header = ast.get_source_segment(raw.decode('ascii'), original_tree.body[0])
    change(header, repr(__doc__))
    constant('SELF', SELF)
    constant('CMDS', CMDS)
    constant('MAKER', MAKER)
    constant('OWNER_PINS', PROFILE_PINS)
    constant('README', README)
    change('    own = ast.parse(inputs[SELF], feature_version=(3, 5))',
           '    own = ast.parse(HOST_RAW, feature_version=(3, 5))')
    change("maker.SCHEMA == 'p011-owner-dispatch-bench-v1-model'",
           "maker.SCHEMA == 'p011-profile-proc-dispatch-bench-v1-model'")
    change("label = 'owner-dispatch-bench'", "label = 'profile-proc-dispatch-bench'")
    change('p011-owner-dispatch-bench-v1;', 'p011-profile-proc-dispatch-bench-v1;')
    change("'receive-owner-dispatch-bench-v1-'", "'receive-profile-proc-dispatch-bench-v1-'")
    change("schema='p011-owner-dispatch-bench-v1-check'",
           "schema='p011-profile-proc-dispatch-bench-v1-check'")
    change('(MOTHER, READ_DONOR, TRANSPORT, MAKER) + OWNER_PINS:',
           '(MOTHER, READ_DONOR, TRANSPORT, MAKER) + OWNER_PINS + EXTRAS:')
    guard = "if __name__ == '__main__':\n    raise SystemExit(main())\n"
    need(current.count(guard.encode('ascii')) == 1, 'bench_original_guard')
    current = current.replace(guard.encode('ascii'), b'', 1)
    restored = current
    for before, after, count in reversed(changes):
        need(restored.count(after) == count, 'bench_finite_reverse')
        restored = restored.replace(after, before)
    need(restored + guard.encode('ascii') == raw, 'bench_complete_byte_inverse')
    need(ast.dump(ast.parse(restored + guard.encode('ascii')), include_attributes=True) ==
         ast.dump(original_tree, include_attributes=True), 'bench_complete_position_ast_inverse')
    old = {node.name: ast.get_source_segment(raw.decode('ascii'), node)
           for node in original_tree.body if isinstance(node, ast.FunctionDef)}
    new = {node.name: ast.get_source_segment(current.decode('ascii'), node)
           for node in ast.parse(current).body if isinstance(node, ast.FunctionDef)}
    need(set(old) == set(new) and all(old[name] == new[name] for name in old
         if name not in ('source_contract', 'run_bench', 'main')), 'bench_original_io_and_stock_helpers_exact')
    return current


def prepare():
    raw = (BASE / CARRIER[0]).read_bytes()
    selected = derive(raw)
    value = types.ModuleType('fixed_profile_proc_dispatch_bench_v1_host')
    value.__file__ = str(BASE / SELF)
    exec(compile(selected, value.__file__, 'exec'), value.__dict__)
    value.__dict__.update(HOST_RAW=selected, EXTRAS=EXTRAS)
    return value


if __name__ == '__main__':
    raise SystemExit(prepare().main())
