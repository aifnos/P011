"""PC-only thin v2 bridge for the frozen status-package v1 SOURCE failure.

V1 rejected the sealer's intentional public/private result hard-link pair;
no v1 bundle/runtime was generated. Preserve that source and failure. Only the
fixed Qt result pair has a two-link reader; all other inputs retain v1's pinned
single-link reader. Default is SOURCE/no writes; --write remains EXCL/27 files.
No old main/test/build, Qt, ADB, runtime Stage, lock or RF is executed.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/formal-send-status-package-v2/generate_ui.py'
V1 = ('candidate/formal-send-status-package-v1/generate_ui.py', 24159,
      'a424b9b28583797ea669beb983437a9ad6a277d527cc808f6160775a6810980c')
RESULT = ('results/formal-send-status-presentation-v1-host-20261006-084552-973b4819/result.json',
          3555, '64714ba0823759436cce100bf5a8b036a82b22a8e5e77ee61996ffed59788add')
PRIVATE_RESULT = ('results/formal-send-status-presentation-v1-host-20261006-084552-973b4819/private-seal/result.json',) + RESULT[1:]
EDITS = (
    (b"ROOT = 'candidate/formal-send-status-package-v1'", b"ROOT = 'candidate/formal-send-status-package-v2'"),
    (b"CONTROL_SUFFIX = '-formal-send-status-package-v1'", b"CONTROL_SUFFIX = '-formal-send-status-package-v2'"),
    (b"'p011-formal-send-status-package-v1-stage'", b"'p011-formal-send-status-package-v2-stage'"),
    (b"'p011-formal-send-status-package-v1-exactsource-delta'", b"'p011-formal-send-status-package-v2-exactsource-delta'"),
    (b"'p011-formal-send-status-package-v1-pc-build'", b"'p011-formal-send-status-package-v2-pc-build'"),
    (b"'p011-formal-send-status-package-v1-generation'", b"'p011-formal-send-status-package-v2-generation'"),
)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directories(path):
    for node in reversed((path,) + tuple(path.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'bridge_directory')


def fixed_file(path, size, links):
    directories(path.parent)
    value = path.lstat()
    need(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
         not getattr(value, 'st_file_attributes', 0) & 0x400 and value.st_size == size and
         value.st_nlink == links, 'bridge_file_identity')
    return meta(value)


def opened_matches(opened, before):
    # Same original PC stat/fstat convention: Windows ctime semantics differ
    # across these interfaces; each interface remains full-metadata stable.
    return opened[:6] == before[:6] if os.name == 'nt' else opened == before


def read_origin():
    path = BASE / V1[0]
    before = fixed_file(path, V1[1], 1)
    with path.open('rb') as stream:
        opened = meta(os.fstat(stream.fileno()))
        need(opened_matches(opened, before), 'bridge_origin_open')
        raw = stream.read(V1[1] + 1)
        need(meta(os.fstat(stream.fileno())) == opened and meta(path.lstat()) == before,
             'bridge_origin_changed')
    need(meta(path.lstat()) == before and (len(raw), digest(raw)) == V1[1:], 'bridge_origin_pin')
    return raw


def read_result_pair():
    """Only these two immutable sealer names; no generic nlink policy change."""
    public, private = BASE / RESULT[0], BASE / PRIVATE_RESULT[0]
    before = (fixed_file(public, RESULT[1], 2), fixed_file(private, RESULT[1], 2))
    need(before[0] == before[1], 'sealed_result_same_identity')
    with public.open('rb') as left, private.open('rb') as right:
        opened = (meta(os.fstat(left.fileno())), meta(os.fstat(right.fileno())))
        need(opened[0] == opened[1] and all(opened_matches(row, old)
             for row, old in zip(opened, before)), 'sealed_result_open_identity')
        values = (left.read(RESULT[1] + 1), right.read(RESULT[1] + 1))
        need((meta(os.fstat(left.fileno())), meta(os.fstat(right.fileno()))) == opened and
             (meta(public.lstat()), meta(private.lstat())) == before, 'sealed_result_held_stability')
    need((meta(public.lstat()), meta(private.lstat())) == before and values[0] == values[1] and
         all((len(raw), digest(raw)) == RESULT[1:] for raw in values), 'sealed_result_pair_pin')
    return values[0]


def derived_module():
    need(os.name == 'nt' and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
         Path(__file__).resolve() == BASE / SELF, 'fixed_pc_bridge')
    origin = read_origin()
    derived = origin
    for old, new in EDITS:
        need(derived.count(old) == 1, 'bridge_forward_unique')
        derived = derived.replace(old, new, 1)
    inverse = derived
    for old, new in reversed(EDITS):
        need(inverse.count(new) == 1, 'bridge_inverse_unique')
        inverse = inverse.replace(new, old, 1)
    original_tree, derived_tree = ast.parse(origin), ast.parse(derived)
    need(inverse == origin and ast.dump(ast.parse(inverse), include_attributes=True) ==
         ast.dump(original_tree, include_attributes=True), 'bridge_complete_byte_ast_inverse')
    # Exclude the old main definition and sole final __main__ guard, rather
    # than importing/executing the failed v1 module's entry point.
    need(isinstance(derived_tree.body[-1], ast.If) and
         ast.dump(derived_tree.body[-1], include_attributes=True) ==
         ast.dump(original_tree.body[-1], include_attributes=True), 'bridge_guard_identity')
    rows = [row for row in derived_tree.body[:-1]
            if not (isinstance(row, ast.FunctionDef) and row.name == 'main')]
    module = types.ModuleType('fixed_status_package_v2_derived_pc_definitions')
    module.__file__ = str(BASE / SELF)
    exec(compile(ast.Module(body=rows, type_ignores=[]), '<fixed-status-package-v2-bridge>', 'exec'), module.__dict__)
    need('main' not in module.__dict__ and module.QT_RESULT == RESULT and module.SELF == SELF and
         module.SESSION == '6d4fb1fd4af949cbb3515870' and
         module.BUNDLE == 'out/mta-ui-send-status-v1-' + module.SESSION, 'bridge_fixed_bindings')
    original_core = module.core_definitions
    def core_definitions():
        core, raw = original_core()
        ordinary_read, ordinary_verify = core['read_pinned'], core['verify_inputs']
        def read_pinned(path, expected):
            if path == BASE / RESULT[0]:
                need(tuple(expected) == RESULT[1:], 'sealed_result_expected_pin')
                return read_result_pair()
            return ordinary_read(path, expected)
        def verify_inputs(inputs):
            cached = read_result_pair()
            need(inputs.get(RESULT[0]) == cached and
                 (PRIVATE_RESULT[0] not in inputs or inputs[PRIVATE_RESULT[0]] == cached) and
                 (V1[0] not in inputs or inputs[V1[0]] == origin), 'sealed_result_cached_identity')
            inputs[PRIVATE_RESULT[0]], inputs[V1[0]] = cached, origin
            ordinary_verify({path: value for path, value in inputs.items()
                             if path not in (RESULT[0], PRIVATE_RESULT[0])})
        core['read_pinned'], core['verify_inputs'] = read_pinned, verify_inputs
        return core, raw
    module.core_definitions = core_definitions
    return module, origin


def _prepare_full():
    module, origin = derived_module()
    outputs, facts, inputs = module.prepare()
    core, ignored = module.core_definitions()
    # The original verifier also covers the newly retained origin. Both fixed
    # result names are always re-read as one pair at every verification point.
    core['verify_inputs'](inputs)
    facts.update(input_count=len(inputs), inputs=[list(core['pin'](path, raw))
        for path, raw in sorted(inputs.items())], bridge_origin=list(V1),
        bridge_replacements=[dict(before=old.decode('ascii'), after=new.decode('ascii'), count=1)
                             for old, new in EDITS],
        bridge_complete_byte_ast_inverse=True, old_v1_main_executed=False,
        sealed_qt_result_pair=[list(RESULT), list(PRIVATE_RESULT)],
        sealed_qt_result_expected_nlink=2, other_source_expected_nlink=1,
        sealed_qt_result_open_and_path_stability=True)
    del outputs[module.GENERATION]
    facts['output_pins'] = [list(core['pin'](path, raw)) for path, raw in sorted(outputs.items())]
    outputs[module.GENERATION] = core['json_raw'](facts)
    need(len(outputs) == facts['output_count'] == 27, 'bridge_original_output_budget')
    return outputs, facts, inputs, module, core


def prepare():
    """Same three-part pure package interface as v1, without executing it."""
    outputs, facts, inputs, module, core = _prepare_full()
    return outputs, facts, inputs


def main():
    need(sys.argv[1:] in ([], ['--write']), 'explicit_write_only')
    writing = sys.argv[1:] == ['--write']
    outputs, facts, inputs, module, core = _prepare_full()
    if writing:
        for folder in (BASE / module.BUNDLE, BASE / module.ROOT / 'runtime'):
            core['safe_directory'](folder.parent)
            need(not os.path.lexists(folder), 'exclusive_directory')
        need(all(not os.path.lexists(BASE / path) for path in outputs), 'exclusive_files')
        core['verify_inputs'](inputs)
        (BASE / module.BUNDLE).mkdir(exist_ok=False)
        for name in ('mta', 'toolbox'): (BASE / module.BUNDLE / name).mkdir(exist_ok=False)
        (BASE / module.ROOT / 'runtime').mkdir(exist_ok=False)
        for path, raw in outputs.items(): core['write_new'](BASE / path, raw)
        core['inventory'](BASE / module.BUNDLE, [path[len(module.BUNDLE)+1:] for path in outputs
            if path.startswith(module.BUNDLE+'/') and path[len(module.BUNDLE)+1:] not in module.PC_NAMES], module.PC_NAMES)
        core['verify_inputs'](inputs)
    print(json.dumps(dict(mode='WRITE_EXCLUSIVE_PC_ONLY' if writing else 'SOURCE_ONLY_NO_WRITES',
        session=module.SESSION, bundle=module.BUNDLE, control=module.CONTROL,
        input_count=len(inputs), output_count=len(outputs),
        outputs=[list(core['pin'](path, raw)) for path, raw in sorted(outputs.items())],
        asset_bytes=facts['asset_bytes'], stage_spare=facts['stage_spare'],
        old_v1_main_executed=False, device=False, rf=False, phone=False, old_tests=0), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
