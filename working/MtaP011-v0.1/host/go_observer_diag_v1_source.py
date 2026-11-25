"""PC-only fixed observer failure-diagnostic source derivation; import is inert.

assemble() reads pinned local source bytes, parses ASTs and returns seven new
files in memory. It never imports/executes target definitions, calls a test,
starts a process or accesses a device. Only explicit --write creates a fresh
candidate prefix with exclusive files. A partial write is retained, not removed.
The diagnostic is PRIVATE failure DATA, never an admission/closure certificate.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1]
PREFIX = 'candidate/go-observer-diag-v1'
OLD_ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
ROOT = '/var/volatile/tmp/p011-mta-go-observer-diag-v1'
OLD_ALIAS = '/tmp/p011-mta-go-observer-libc-v1'
ALIAS = '/tmp/p011-mta-go-observer-diag-v1'
CATALOG = 'candidate/go-observer-libc-v1/assets/observer-source-catalog.json'
CATALOG_PIN = (15861, '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
PARENT = 'candidate/go-observer-libc-v1/runtime/mta_go_readonly_parent.py'
PARENT_PIN = (52881, 'a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6')
ROLES = ('mta_go_readonly_preflight', 'mta_go_readonly_loader',
         'mta_go_readonly_entry', 'mta_go_readonly_parent')
MOTHER_PINS = ((64948, '802ad7c3b80ea6e9ea4678a4112bd2ec95be08cff5fe6684e1162f127ae55f44'),
               (36543, '8e60e8f86a0cd4a261ca65f657739e9189137cf37dc04f4af1495263ce1b8e56'),
               (45310, 'b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa'),
               PARENT_PIN)
OLD_EXCEPT = b'    except BaseException: return 1  # Failure/partial inventory stays original and private.\r\n'
NEW_EXCEPT = b'    except BaseException as error: _private_failure_diag(value, error); return 1  # Original failure retained.\r\n'
GUARD = b"if __name__ == '__main__':\r\n    raise SystemExit(main94())\r\n"
BUILTIN_ERRORS = ('BaseException', 'Exception', 'OSError', 'ValueError', 'TypeError',
    'RuntimeError', 'AssertionError', 'AttributeError', 'KeyError', 'IndexError',
    'ImportError', 'SyntaxError', 'MemoryError', 'OverflowError', 'UnicodeError',
    'NameError', 'StopIteration', 'NotImplementedError', 'ZeroDivisionError',
    'FileNotFoundError', 'PermissionError', 'TimeoutError', 'InterruptedError', 'BlockingIOError')

# Literal tables below are derived only from authenticated source ASTs. Runtime
# exports numeric table indices, never arbitrary exception strings/paths/IDs.
HELPER_TEMPLATE = '''
# Private failure DATA only. FD2 identity/nonblocking/closure is NOT certified.
_PRIVATE_DIAG_TYPES = @TYPES@
_PRIVATE_DIAG_REASONS = @REASONS@
_PRIVATE_DIAG_FRAMES = @FRAMES@


def _private_failure_diag(value, caught):
    try:
        if (type(value) is not ReadonlyObserverEntry or not _ENTRY_INVENTORY or
                _ENTRY_INVENTORY[-1] is not value or not isinstance(caught, BaseException)):
            return
        # All reads below are retained Python caches, not current device proofs.
        same = int(caught is object.__getattribute__(value, 'failure'))
        layers, seen, current, edge, chain_cut = [], [], caught, 0, 0
        for unused in range(4):
            seen.append(current)
            current_type, type_code = type(current), 0
            for module_name, class_name, number in _PRIVATE_DIAG_TYPES:
                module = sys.modules.get(module_name)
                if (type(module) is types.ModuleType and
                        module.__dict__.get(class_name) is current_type):
                    type_code = number
                    break
            fields = object.__getattribute__(current, '__dict__')
            code = fields.get('code') if type(fields) is dict else None
            reason = (_PRIVATE_DIAG_REASONS.get(code, 0)
                if type(code) is str and 1 <= len(code) <= 96 else 0)
            if not reason:
                args = BaseException.args.__get__(current, current_type)
                if (type(args) is tuple and len(args) == 1 and type(args[0]) is str
                        and 1 <= len(args[0]) <= 96):
                    reason = _PRIVATE_DIAG_REASONS.get(args[0], 0)
            number = 0
            if isinstance(current, OSError):
                actual = OSError.errno.__get__(current, current_type)
                if type(actual) is int and 1 <= actual <= 4095:
                    number = actual
            trace = BaseException.__traceback__.__get__(current, current_type)
            positions = []
            for unused_frame in range(8):
                if trace is None:
                    break
                namespace, frame_code = trace.tb_frame.f_globals, trace.tb_frame.f_code
                module_name, function_name = namespace.get('__name__'), frame_code.co_name
                canonical = sys.modules.get(module_name) if type(module_name) is str else None
                frame_id = (_PRIVATE_DIAG_FRAMES.get((module_name, function_name), 0)
                    if type(canonical) is types.ModuleType and canonical.__dict__ is namespace
                    and type(function_name) is str else 0)
                line = trace.tb_lineno
                if type(line) is not int or not 1 <= line <= 65535:
                    line = 0
                positions.append(str(frame_id) + ':' + str(line))
                trace = trace.tb_next
            trace_cut = int(trace is not None)
            suppressed = BaseException.__suppress_context__.__get__(current, current_type)
            layers.append(','.join((str(type_code), str(reason), str(number), str(edge),
                str(int(suppressed is True)), str(trace_cut), '|'.join(positions))))
            cause = BaseException.__cause__.__get__(current, current_type)
            context = BaseException.__context__.__get__(current, current_type)
            following, next_edge = ((cause, 1) if isinstance(cause, BaseException)
                else ((context, 2) if isinstance(context, BaseException) else (None, 0)))
            if following is None:
                break
            if any(following is item for item in seen):
                chain_cut = 2
                break
            if len(layers) == 4:
                chain_cut = 1
                break
            current, edge = following, next_edge
        raw = ('PRIVATE_GO_OBSERVER_FAILURE_V1 s=' + str(same) + ' x=' + str(chain_cut)
            + ' e=' + ';'.join(layers) + '\\n').encode('ascii')
        if 1 <= len(raw) <= 512:
            # Exactly one attempt; no flag/stat/clock/read/close/retry operation.
            # A failed/short write is not retried and cannot change main return1.
            os.write(2, raw)
    except BaseException:
        pass


'''


def _require(condition, label):
    if not condition:
        raise ValueError(label)


def _pin(raw):
    _require(type(raw) is bytes, 'source_bytes_type')
    return len(raw), hashlib.sha256(raw).hexdigest()


def _json(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')


def _local(path):
    _require(type(path) is str and path and '\\' not in path and
        not Path(path).is_absolute() and '..' not in Path(path).parts, 'fixed_path')
    result = (BASE / path).resolve()
    _require(result.is_relative_to(BASE) and result != BASE, 'fixed_path_escape')
    return result


def _mother_catalog(raw):
    _require(_pin(raw) == CATALOG_PIN, 'mother_catalog_pin')
    value = json.loads(raw.decode('ascii'))
    _require(value['schema'] == 'p011-go-observer-libc-v1-fixed-asset-catalog' and
        value['root'] == OLD_ROOT and value['alias'] == OLD_ALIAS and
        value['source_count'] == 41 and value['source_bytes'] == 1442508 and
        value['load_count'] == 38 and len(value['files']) == 41 and
        sum(row['bytes'] for row in value['files']) == 1442508 and
        len({row['module'] for row in value['files']}) == 41 and
        len({row['source'] for row in value['files']}) == 41 and
        value['parent_inline_only']['source'] == PARENT and
        (value['parent_inline_only']['bytes'], value['parent_inline_only']['sha256']) == PARENT_PIN,
        'mother_catalog_shape')
    for row in value['files']:
        _require(set(row) == {'module', 'source', 'target', 'bytes', 'sha256', 'mode'} and
            row['mode'] == '0400' and row['target'] == OLD_ROOT + '/runtime/' + row['module'] + '.py',
            'mother_role_shape')
    for role, pin in zip(ROLES[:3], MOTHER_PINS[:3]):
        row = next(item for item in value['files'] if item['module'] == role)
        _require((row['bytes'], row['sha256']) == pin, 'mother_role_pin')
    return value


def source_inputs():
    """Fixed local source contracts, not target/device observation."""
    catalog = _mother_catalog(_local(CATALOG).read_bytes())
    return ((CATALOG,) + CATALOG_PIN,) + tuple((row['source'], row['bytes'], row['sha256'])
        for row in catalog['files']) + ((PARENT,) + PARENT_PIN,)


def load_inputs():
    """Read fixed PC source bytes only; imported target code is never executed."""
    result = {}
    for path, size, sha in source_inputs():
        raw = _local(path).read_bytes()
        _require(_pin(raw) == (size, sha), 'fixed_input_pin:' + path)
        result[path] = raw
    return result


def _tree(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def _definitions(raw, skip_main=False):
    return [(type(node).__name__, node.name, node.lineno, ast.dump(node, include_attributes=False))
        for node in ast.walk(_tree(raw)) if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        and not (skip_main and node.name in ('main', '_private_failure_diag'))]


def _tables(catalog, inputs):
    classes = {('builtins', name) for name in BUILTIN_ERRORS}
    functions, reasons = set(), {}
    for row in catalog['files']:
        module, path = row['module'], row['source']
        tree = _tree(inputs[path])
        functions.add((module, '<module>'))
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                _require(node.lineno <= 65535, 'source_line_cap')
                if isinstance(node, ast.FunctionDef):
                    functions.add((module, node.name))
                elif node.name.endswith(('Error', 'Exception')):
                    classes.add((module, node.name))
            comp = {ast.GeneratorExp: '<genexpr>', ast.ListComp: '<listcomp>',
                    ast.DictComp: '<dictcomp>', ast.SetComp: '<setcomp>', ast.Lambda: '<lambda>'}
            if type(node) in comp:
                functions.add((module, comp[type(node)]))
            strings, kind = (), None
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args and
                    (node.func.id == '_fail' or node.func.id.endswith(('Error', 'Exception')))):
                try:
                    constant = ast.literal_eval(node.args[0])
                except (ValueError, TypeError, SyntaxError):
                    constant = None
                if type(constant) is str:
                    strings, kind = (constant,), 'literal_failure_call'
            if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                    target.id == '_CODES' for target in node.targets) and
                    isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and
                    node.value.func.id == 'frozenset' and len(node.value.args) == 1):
                strings, kind = ast.literal_eval(node.value.args[0]), 'literal_codes_enum'
            for text in strings:
                if type(text) is str and re.fullmatch('[a-z][a-z0-9_]{0,95}', text):
                    reasons.setdefault(text, []).append({'source': path, 'line': node.lineno, 'kind': kind})
    # The named Entry is executed as __main__; aliases reuse the same frame/type IDs.
    type_map = [(module, name, index + 1) for index, (module, name) in enumerate(sorted(classes))]
    type_map += [('__main__', name, index) for module, name, index in type_map
                 if module == 'mta_go_readonly_entry']
    frame_map = {key: index + 1 for index, key in enumerate(sorted(functions))}
    frame_map.update({('__main__', name): number for (module, name), number in list(frame_map.items())
                      if module == 'mta_go_readonly_entry'})
    reason_map = {name: index + 1 for index, name in enumerate(sorted(reasons))}
    _require(max(item[2] for item in type_map) <= 255 and len(reason_map) <= 4095 and
        max(frame_map.values()) <= 4095, 'diagnostic_numeric_table_caps')
    helper = HELPER_TEMPLATE.replace('@TYPES@', repr(tuple(type_map))).replace(
        '@REASONS@', repr(reason_map)).replace('@FRAMES@', repr(frame_map)).encode('ascii')
    helper = helper.replace(b'\n', b'\r\n')
    # Maximum: four layers, each eight ID:line frames and seven finite columns.
    worst_layer = '255,4095,4095,2,1,1,' + '|'.join(['4095:65535'] * 8)
    worst = ('PRIVATE_GO_OBSERVER_FAILURE_V1 s=1 x=2 e=' + ';'.join([worst_layer] * 4) + '\n').encode('ascii')
    _require(len(worst) <= 512 and _tree(helper), 'diagnostic_record_bound')
    codes = {'types': [list(item) for item in type_map],
        'reasons': [{'number': reason_map[name], 'reason': name, 'sources': reasons[name]}
                    for name in sorted(reasons)],
        'frames': [{'module': key[0], 'function': key[1], 'number': frame_map[key]}
                   for key in sorted(frame_map)], 'maximum_record_bytes': len(worst),
        'frame_projection': 'namespace_bound_name_and_original_lineno',
        'exact_original_function_or_code_identity_certified': False,
        'layer_columns': ['type', 'reason', 'errno', 'edge_0_root_1_cause_2_context',
            'suppress_context', 'tb_truncated', 'frame_id_colon_original_lineno'],
        'chain_cut_0_complete_1_layer_cap_2_cycle': True}
    return helper, codes


def _edit(raw, before, after, edits, count=1):
    _require(type(before) is bytes and type(after) is bytes and before != after and
        type(count) is int and count >= 1 and raw.count(before) == count, 'exact_forward_edit')
    value = raw.replace(before, after)
    _require(value.count(after) == count and value.replace(after, before) == raw, 'exact_reverse_edit')
    edits.append({'before': before.decode('ascii'), 'after': after.decode('ascii'), 'count': count})
    return value


def _root(raw, alias_name, edits):
    raw = _edit(raw, ("ROOT = '" + OLD_ROOT + "'\r\n").encode('ascii'),
        ("ROOT = '" + ROOT + "'\r\n").encode('ascii'), edits)
    if alias_name:
        raw = _edit(raw, (alias_name + " = '" + OLD_ALIAS + "'\r\n").encode('ascii'),
            (alias_name + " = '" + ALIAS + "'\r\n").encode('ascii'), edits)
    return raw


def assemble(inputs=None):
    """Return {'files': tuple({'path', 'raw'}), 'facts': dict}; never write/run."""
    inputs = load_inputs() if inputs is None else inputs
    _require(type(inputs) is dict and CATALOG in inputs, 'input_mapping')
    catalog = _mother_catalog(inputs[CATALOG])
    contracts = ((CATALOG,) + CATALOG_PIN,) + tuple((row['source'], row['bytes'], row['sha256'])
        for row in catalog['files']) + ((PARENT,) + PARENT_PIN,)
    _require(set(inputs) == {item[0] for item in contracts}, 'exact_source_input_keys')
    for path, size, sha in contracts:
        _require(_pin(inputs[path]) == (size, sha), 'fixed_input_pin:' + path)
    helper, codes = _tables(catalog, inputs)
    mothers = {row['module']: inputs[row['source']] for row in catalog['files'] if row['module'] in ROLES}
    mothers[ROLES[3]] = inputs[PARENT]
    changed, delta_rows = {}, []
    for index, role in enumerate(ROLES):
        mother, edits = mothers[role], []
        _require(_pin(mother) == MOTHER_PINS[index], 'mother_actual_pin')
        raw = _root(mother, None if index == 0 else ('ALIAS_ROOT' if index == 1 else 'ALIAS'), edits)
        if index == 1:
            size, sha = _pin(changed[ROLES[0]])
            before = ("    ('mta_go_readonly_preflight', 64948, '" + MOTHER_PINS[0][1] + "'),\r\n").encode('ascii')
            after = ("    ('mta_go_readonly_preflight', " + str(size) + ", '" + sha + "'),\r\n").encode('ascii')
            raw = _edit(raw, before, after, edits)
        elif index == 2:
            size, sha = _pin(changed[ROLES[1]])
            before = ("    ('mta_go_readonly_loader', 36543,\r\n     '" + MOTHER_PINS[1][1] + "'),\r\n").encode('ascii')
            after = ("    ('mta_go_readonly_loader', " + str(size) + ",\r\n     '" + sha + "'),\r\n").encode('ascii')
            raw = _edit(raw, before, after, edits)
            raw = _edit(raw, OLD_EXCEPT, NEW_EXCEPT, edits)
            _require(not any(name in mother.decode('ascii') for name in
                ('_private_failure_diag', '_PRIVATE_DIAG_TYPES', '_PRIVATE_DIAG_REASONS', '_PRIVATE_DIAG_FRAMES')),
                'private_name_collision')
            raw = _edit(raw, GUARD, helper + GUARD, edits)
        elif index == 3:
            size, sha = _pin(changed[ROLES[2]])
            before = ("ENTRY_PIN = ('mta_go_readonly_entry', 45310,\r\n             '" + MOTHER_PINS[2][1] + "')\r\n").encode('ascii')
            after = ("ENTRY_PIN = ('mta_go_readonly_entry', " + str(size) + ",\r\n             '" + sha + "')\r\n").encode('ascii')
            raw = _edit(raw, before, after, edits)
        _tree(raw)
        inverse = raw
        for item in reversed(edits):
            before, after = item['before'].encode('ascii'), item['after'].encode('ascii')
            _require(inverse.count(after) == item['count'], 'full_inverse_anchor')
            inverse = inverse.replace(after, before)
        _require(inverse == mother and _tree(inverse), 'full_byte_ast_inverse')
        _require(_definitions(raw, index == 2) == _definitions(mother, index == 2), 'business_definitions_changed')
        changed[role] = raw
        delta_rows.append({'module': role, 'old': dict(zip(('bytes', 'sha256'), _pin(mother))),
            'new': dict(zip(('bytes', 'sha256'), _pin(raw))), 'edits': edits,
            'complete_byte_ast_inverse': True, 'original_definition_count': len(_definitions(mother)),
            'business_definitions_unchanged_except_entry_main': True})
    new_catalog = json.loads(inputs[CATALOG].decode('ascii'))
    new_catalog['schema'] = 'p011-go-observer-diag-v1-fixed-asset-catalog'
    new_catalog['root'], new_catalog['alias'] = ROOT, ALIAS
    for row in new_catalog['directories']:
        row['path'] = row['path'].replace(OLD_ROOT, ROOT)
    for row in new_catalog['files']:
        row['target'] = ROOT + '/runtime/' + row['module'] + '.py'
        if row['module'] in changed:
            row['source'] = PREFIX + '/runtime/' + row['module'] + '.py'
            row['bytes'], row['sha256'] = _pin(changed[row['module']])
    new_catalog['source_bytes'] = sum(row['bytes'] for row in new_catalog['files'])
    new_catalog['parent_inline_only'].update(source=PREFIX + '/runtime/' + ROLES[3] + '.py',
        bytes=_pin(changed[ROLES[3]])[0], sha256=_pin(changed[ROLES[3]])[1])
    _require(new_catalog['source_bytes'] <= new_catalog['program_cap_bytes'], 'unchanged_program_cap')
    unchanged = [row for row in new_catalog['files'] if row['module'] not in changed]
    _require(len(unchanged) == 38 and all(_pin(inputs[row['source']]) == (row['bytes'], row['sha256'])
        for row in unchanged), '38_actual_unchanged_roles')
    # Keep the frozen catalog formatting/order and prove an actual byte inverse.
    catalog_raw, catalog_edits = inputs[CATALOG], []
    catalog_raw = _edit(catalog_raw, b'p011-go-observer-libc-v1-fixed-asset-catalog',
        b'p011-go-observer-diag-v1-fixed-asset-catalog', catalog_edits)
    catalog_raw = _edit(catalog_raw, OLD_ROOT.encode('ascii'), ROOT.encode('ascii'),
        catalog_edits, 1 + len(catalog['directories']) + len(catalog['files']))
    catalog_raw = _edit(catalog_raw, OLD_ALIAS.encode('ascii'), ALIAS.encode('ascii'), catalog_edits)
    catalog_raw = _edit(catalog_raw, b'candidate/go-observer-libc-v1/runtime/',
        (PREFIX + '/runtime/').encode('ascii'), catalog_edits, 4)
    for index, role in enumerate(ROLES):
        indent = '    ' if index == 3 else '      '
        old_size, old_sha = MOTHER_PINS[index]
        new_size, new_sha = _pin(changed[role])
        before = ('"bytes": ' + str(old_size) + ',\n' + indent + '"sha256": "' + old_sha + '"').encode('ascii')
        after = ('"bytes": ' + str(new_size) + ',\n' + indent + '"sha256": "' + new_sha + '"').encode('ascii')
        catalog_raw = _edit(catalog_raw, before, after, catalog_edits)
    catalog_raw = _edit(catalog_raw, b'"source_bytes": 1442508,',
        ('"source_bytes": ' + str(new_catalog['source_bytes']) + ',').encode('ascii'), catalog_edits)
    _require(json.loads(catalog_raw.decode('ascii')) == new_catalog, 'catalog_exact_object')
    catalog_inverse = catalog_raw
    for item in reversed(catalog_edits):
        before, after = item['before'].encode('ascii'), item['after'].encode('ascii')
        _require(catalog_inverse.count(after) == item['count'], 'catalog_inverse_anchor')
        catalog_inverse = catalog_inverse.replace(after, before)
    _require(catalog_inverse == inputs[CATALOG], 'catalog_complete_byte_inverse')
    facts = {'schema': 'p011-go-observer-diag-v1-source-facts', 'scope': 'SOURCE_ONLY_NOT_STAGED_NOT_RUN',
        'root': ROOT, 'alias': ALIAS, 'source_count': 41, 'source_bytes': new_catalog['source_bytes'],
        'changed_asset_count': 3, 'unchanged_asset_count': 38, 'load_count': 38,
        'parent_inline_only': new_catalog['parent_inline_only'], 'source_inputs': [list(item) for item in contracts],
        'runtime_pins': {role: dict(zip(('bytes', 'sha256'), _pin(raw))) for role, raw in changed.items()},
        'diagnostic_max_bytes': 512, 'exception_layers': 4, 'tb_frames_per_layer': 8,
        'tb_frames_total': 32, 'diagnostic_single_fixed_fd2_attempt': True,
        'frame_projection': 'namespace_bound_name_and_original_lineno',
        'exact_original_function_or_code_identity_certified': False,
        'stderr_identity_nonblocking_closure_certified': False, 'successful_packet_unchanged': True,
        'terminal_definitions_unchanged': True, 'original_proc_unchanged': True,
        'device_accessed': False, 'tests_invoked': 0, 'target_definitions_executed': 0,
        'rf_requested': False, 'stager_included': False}
    outputs = [{'path': PREFIX + '/runtime/' + role + '.py', 'raw': changed[role]} for role in ROLES]
    outputs.append({'path': PREFIX + '/assets/observer-source-catalog.json', 'raw': catalog_raw})
    outputs.append({'path': PREFIX + '/assets/delta.json', 'raw': _json({'schema': 'p011-go-observer-diag-v1-exact-delta',
        'roles': delta_rows, 'diagnostic_codes': codes, 'catalog_edits': catalog_edits,
        'catalog_complete_byte_inverse': True})})
    outputs.append({'path': PREFIX + '/assets/generation.json', 'raw': _json({'schema': 'p011-go-observer-diag-v1-generation',
        'generated_by': 'host/go_observer_diag_v1_source.py', 'facts': facts,
        'outputs': [{'path': item['path'], 'bytes': _pin(item['raw'])[0], 'sha256': _pin(item['raw'])[1]}
                    for item in outputs]})})
    _require(len(outputs) == 7 and len({item['path'] for item in outputs}) == 7, 'seven_exclusive_outputs')
    return {'files': tuple(outputs), 'facts': facts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Create the one new candidate prefix exclusively; never run it.')
    args = parser.parse_args(argv)
    result = assemble()
    if args.write:
        destination = _local(PREFIX)
        _require(not destination.exists(), 'new_candidate_prefix_already_exists')
        destination.mkdir()  # No parents=True and no adoption of an existing prefix.
        (destination / 'runtime').mkdir()
        (destination / 'assets').mkdir()
        for item in result['files']:
            with _local(item['path']).open('xb') as stream:
                _require(stream.write(item['raw']) == len(item['raw']), 'short_pc_file_write')
        for item in result['files']:
            _require(_local(item['path']).read_bytes() == item['raw'], 'pc_generated_readback')
    print(json.dumps({'mode': 'WRITE_SOURCE_ONLY' if args.write else 'SOURCE_ONLY_NO_WRITE',
        'files': [{'path': item['path'], 'bytes': _pin(item['raw'])[0], 'sha256': _pin(item['raw'])[1]}
                  for item in result['files']], 'facts': result['facts']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
