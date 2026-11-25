"""Independent retained-cache and retained-collect-error diagnostics, not admission.

Pure target functions read held dictionaries/code/tracebacks after run_fixed.
No clock, IO, status, close, new observation or arbitrary exception text.
"""
import ast
import types

CACHE_PREFIX = 'PRIVATE_STARTUP_RETAINED_CACHE_V2='
ERROR_PREFIX = 'PRIVATE_STARTUP_RETAINED_COLLECT_ERROR_V2='
FUNCTIONS = ('_private_startup_retained_context_v2', '_private_startup_retained_cache_v2',
             '_private_startup_retained_collect_error_v2')


def _private_startup_retained_context_v2(retained, session):
    try:
        if type(session) is not types.ModuleType:
            return None
        shared = session.__dict__
        cls = shared.get('FixedSession')
        if type(cls) is not type or type(retained) is not cls or shared.get('_RETAINED') is not retained:
            return None
        saved = retained.__dict__
        owner, loader, own_module = saved.get('owner'), saved.get('loader'), saved.get('owner_module')
        if type(own_module) is not types.ModuleType:
            return None
        own_ns = own_module.__dict__
        owner_type = own_ns.get('FixedStateServiceOwner')
        if type(owner_type) is not type or type(owner) is not owner_type:
            return None
        owned = owner.__dict__
        if (owned.get('loader') is not loader or owned.get('_startup_namespace_original') is not own_ns or
                owned.get('_startup_owner_type_original') is not owner_type):
            return None
        modules, system = loader.__dict__.get('modules'), shared.get('sys')
        if type(modules) is not dict or type(system) is not types.ModuleType:
            return None
        factory_module = modules.get('mta_client_receive_factory')
        if (type(factory_module) is not types.ModuleType or
                system.modules.get('mta_client_receive_factory') is not factory_module):
            return None
        ns = factory_module.__dict__
        scope_type, factory_type = ns.get('_StartupReadScope'), ns.get('FixedReceiveDeploymentFactory')
        originals, codes = ns.get('_STARTUP_ALIAS_ORIGINALS'), ns.get('_STARTUP_ALIAS_CODES')
        if (type(scope_type) is not type or type(factory_type) is not type or
                type(originals) is not tuple or len(originals) != 6 or type(codes) is not tuple or len(codes) != 6):
            return None
        check = scope_type.__dict__.get('check_active')
        if (type(check) is not types.FunctionType or check is not originals[2] or
                check.__code__ is not codes[2] or check.__globals__ is not ns):
            return None
        scope, factory = saved.get('startup_scope'), owned.get('factory')
        if type(scope) is not scope_type or type(factory) is not factory_type:
            return None
        cached, made = scope.__dict__, factory.__dict__
        if (scope is not owned.get('startup_scope') or scope is not owned.get('_startup_scope_original') or
                scope is not made.get('_startup_scope') or factory is not owned.get('_startup_factory_original') or
                cached.get('owner') is not owner or cached.get('factory') is not factory or
                cached.get('_alias_functions') is not originals or cached.get('_alias_codes') is not codes):
            return None
        return saved, owned, cached, modules, system, ns, scope
    except BaseException:
        return None


def _private_startup_retained_cache_v2(retained, session):
    unknown = dict(available=False, unknown=True, values=None, prepare_same_object=None, postimport_is_last=None)
    try:
        context = _private_startup_retained_context_v2(retained, session)
        if context is None:
            return unknown
        cached, scope = context[2], context[6]
        names = ('startup_boundary_init', 'startup_boundary_private_sources', 'startup_boundary_wpa',
                 'startup_boundary_profile', 'startup_boundary_postimport', 'last', 'prepare_until',
                 'original_prepare_until', 'original_until')
        if any(name not in cached for name in names):
            return unknown
        before = tuple(cached.get(name) for name in names)
        after = tuple(cached.get(name) for name in names)
        if (scope.__dict__ is not cached or any(a is not b for a, b in zip(before, after)) or
                any(v is not None and (type(v) is not float or not 0 <= v < 1e12) for v in before)):
            return unknown
        return dict(available=True, unknown=False, values=before,
                    prepare_same_object=None if before[6] is None or before[7] is None else before[6] is before[7],
                    postimport_is_last=None if before[4] is None or before[5] is None else before[4] is before[5])
    except BaseException:
        return unknown


def _private_startup_retained_collect_error_v2(retained, session):
    unknown = dict(available=False, unknown=True, kind=None, errno=None, code=None, trace=None)
    try:
        context = _private_startup_retained_context_v2(retained, session)
        if context is None:
            return unknown
        saved, owned, cached, modules, system, factory_ns, scope = context
        private, rows = cached.get('private_modules'), cached.get('module_originals')
        if type(private) is not dict or type(rows) is not tuple or len(rows) != 35:
            return unknown
        namespaces = {}
        for name in ('mta_client_baseline', 'mta_client_proc', 'mta_client_wpa_status', 'mta_client_files'):
            matches = [r for r in rows if type(r) is tuple and len(r) == 3 and type(r[0]) is str and r[0] == name]
            if len(matches) != 1:
                return unknown
            row, module = matches[0], private.get(name)
            if type(module) is not types.ModuleType or row[1] is not module or row[2] is not module.__dict__:
                return unknown
            namespaces[name] = row[2]
        startup = modules.get('mta_client_startup_readonly')
        if (type(startup) is not types.ModuleType or system.modules.get('mta_client_startup_readonly') is not startup or
                owned.get('_startup_module_original') is not startup):
            return unknown
        startup_ns = startup.__dict__
        collection_type = startup_ns.get('StartupCollection')
        ticket = cached.get('collector_ticket')
        if (type(collection_type) is not type or collection_type is not owned.get('_startup_collection_type_original') or
                type(ticket) is not dict or ticket.get('creator') is not collection_type or
                ticket.get('started') is not True or ticket.get('ended') is not True):
            return unknown
        value, outer = ticket.get('returned'), saved.get('first_error')
        if type(value) is not collection_type or saved.get('startup_collection') is not value:
            return unknown
        collection = value.__dict__
        if (collection.get('scope') is not scope or collection.get('_scope_original') is not scope or
                collection.get('modules') is not private or collection.get('_modules_original') is not private or
                collection.get('failure') is not outer or ticket.get('failure') is not outer or
                owned.get('startup_failure') is not outer):
            return unknown
        base_ns = namespaces['mta_client_baseline']
        base_type, error_type = base_ns.get('BaselineCollector'), base_ns.get('BaselineError')
        if type(base_type) is not type or type(error_type) is not type or type(outer) is not error_type:
            return unknown
        outer_code = outer.__dict__.get('code')
        if type(outer_code) is not str or outer_code != 'io_error':
            return unknown
        definitions, native = collection.get('_definitions'), collection.get('_native_class')
        collect = base_type.__dict__.get('collect')
        if (type(definitions) is not tuple or len(definitions) != 23 or definitions[0] is not base_type or
                type(collect) is not types.FunctionType or definitions[1] is not collect or
                collect.__globals__ is not base_ns or type(native) is not type or native.__bases__ != (base_type,)):
            return unknown
        collector = collection.get('collector')
        if type(collector) is not native or collector is not collection.get('_collector_original'):
            return unknown
        ledger = collector.__dict__
        reason = ledger.get('_reason')
        if ledger.get('_ended') is not True or type(reason) is not str or reason != 'io_error':
            return unknown
        matches, cursor = [], outer.__traceback__
        for unused in range(32):
            if cursor is None:
                break
            frame = cursor.tb_frame
            if frame.f_globals is base_ns and frame.f_code is collect.__code__ and frame.f_locals.get('self') is collector:
                matches.append(frame)
            cursor = cursor.tb_next
        if cursor is not None or len(matches) != 1:
            return unknown
        frame = matches[0]
        error = frame.f_locals.get('error')
        if not isinstance(error, BaseException) or error is outer or frame.f_locals.get('error') is not error:
            return unknown
        kind, code, number = 'other', None, None
        builtins = ((ValueError, 'ValueError'), (TypeError, 'TypeError'), (RuntimeError, 'RuntimeError'),
                    (AssertionError, 'AssertionError'), (OSError, 'OSError'), (FileNotFoundError, 'FileNotFoundError'),
                    (PermissionError, 'PermissionError'), (TimeoutError, 'TimeoutError'), (InterruptedError, 'InterruptedError'))
        for cls, label in builtins:
            if type(error) is cls:
                kind = label
        for name, class_name, whitelist in (('mta_client_baseline', 'BaselineError', '_CODES'),
                                            ('mta_client_proc', 'ProcReadError', '_CODES'),
                                            ('mta_client_wpa_status', 'WpaStatusError', '_REASONS'),
                                            ('mta_client_files', 'ClientFileError', '_CODES')):
            ns = namespaces[name]
            cls, allowed = ns.get(class_name), ns.get(whitelist)
            if type(cls) is type and type(error) is cls:
                kind = class_name
                candidate = error.__dict__.get('code')
                if (type(allowed) is frozenset and len(allowed) <= 128 and
                        all(type(item) is str and len(item) <= 64 for item in allowed) and type(candidate) is str and
                        len(candidate) <= 64 and candidate in allowed):
                    code = candidate
        startup_error = startup_ns.get('StartupReadError')
        if type(startup_error) is type and type(error) is startup_error:
            kind = 'StartupReadError'
            candidate, allowed = error.__dict__.get('code'), startup_ns.get('_CODES')
            if (type(allowed) is frozenset and len(allowed) <= 128 and
                    all(type(item) is str and len(item) <= 64 for item in allowed) and type(candidate) is str and
                    len(candidate) <= 64 and candidate in allowed):
                code = candidate
        publication_error = factory_ns.get('ReceivePublicationError')
        if type(publication_error) is type and type(error) is publication_error:
            kind = 'ReceivePublicationError'  # No code attribute; never inspect its args.
        if kind in ('OSError', 'FileNotFoundError', 'PermissionError', 'TimeoutError', 'InterruptedError'):
            candidate = error.errno
            if candidate is not None and (type(candidate) is not int or not 0 <= candidate <= 65535):
                return unknown
            number = candidate
        holders = ((base_ns, 'mta_client_baseline', base_type,
                    ('collect', '_now', '_open', '_read_file', '_proc', '_actors', '_interfaces', '_status', '_binary_parents')),
                   (namespaces['mta_client_proc'], 'mta_client_proc', namespaces['mta_client_proc'].get('ProcReader'),
                    ('__init__', '_begin', '_observe', '_observe_body', '_actor_pass', '_now', '_originals',
                     '_read', '_open', 'read_self', 'read_actor')),
                   (startup_ns, 'mta_client_startup_readonly', collection_type, ('_now', '_originals', '_status', 'run')),
                   (startup_ns, 'mta_client_startup_readonly', native, ('_open', '_status')),
                   (factory_ns, 'mta_client_receive_factory', factory_ns.get('_StartupReadScope'),
                    ('check_active', '_originals', 'alias_now')),
                   (base_ns, 'mta_client_baseline', base_ns.get('_LinuxIo'),
                    ('validate', 'open', 'read', 'stat', 'fstat')),
                   (namespaces['mta_client_wpa_status'], 'mta_client_wpa_status',
                    namespaces['mta_client_wpa_status'].get('_LinuxIo'), ('validate', 'open', 'read', 'stat', 'fstat')))
        bound = []
        for ns, module_name, cls, names in holders:
            if type(cls) is not type:
                continue
            for name in names:
                fn = cls.__dict__.get(name)
                if type(fn) is types.FunctionType and fn.__globals__ is ns:
                    bound.append((ns, fn.__code__, module_name, name))
        for ns, module_name in ((base_ns, 'mta_client_baseline'),
                                (namespaces['mta_client_proc'], 'mta_client_proc'),
                                (startup_ns, 'mta_client_startup_readonly'),
                                (factory_ns, 'mta_client_receive_factory')):
            for name in ('_fail', '_metadata'):
                fn = ns.get(name)
                if type(fn) is types.FunctionType and fn.__globals__ is ns:
                    bound.append((ns, fn.__code__, module_name, name))
        trace, cursor = [], error.__traceback__
        for unused in range(32):
            if cursor is None:
                break
            frame, line = cursor.tb_frame, cursor.tb_lineno
            if type(line) is not int or not 1 <= line <= 1000000:
                return unknown
            selected = [(module_name, name) for ns, fn_code, module_name, name in bound
                        if frame.f_globals is ns and frame.f_code is fn_code]
            label = selected[0] if len(selected) == 1 else ('unknown', 'unknown')
            trace.append((label[0], label[1], line))
            cursor = cursor.tb_next
        if cursor is not None:
            return unknown
        return dict(available=True, unknown=False, kind=kind, errno=number, code=code, trace=tuple(trace))
    except BaseException:
        return unknown


def target_fragment(raw):
    text = raw.decode('ascii')
    tree = ast.parse(text, feature_version=(3, 5))
    rows = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
    if tuple(n.name for n in rows) != FUNCTIONS or any(n.decorator_list for n in rows):
        raise ValueError('fixed_three_target_functions')
    functions = '\n\n'.join(ast.get_source_segment(text, n) for n in rows)
    tail = ("\ntry:\n print('PRIVATE_STARTUP_RETAINED_CACHE_V2='+repr(_private_startup_retained_cache_v2(retained,session)))\n"
            " print('PRIVATE_STARTUP_RETAINED_COLLECT_ERROR_V2='+repr(_private_startup_retained_collect_error_v2(retained,session)))\n"
            "except BaseException:\n pass\n")
    fragment = (functions + tail).encode('ascii')
    if len(fragment) > 16384 or max(map(len, fragment.splitlines())) > 256:
        raise ValueError('fixed_private_fragment_cap')
    return fragment


def inject(program, raw):
    anchor = b'retained=session._RETAINED\n'
    fragment = target_fragment(raw)
    if type(program) is not bytes or program.count(anchor) != 1 or CACHE_PREFIX.encode('ascii') in program:
        raise ValueError('one_after_return_anchor')
    current = program.replace(anchor, anchor + fragment)
    if current.replace(anchor + fragment, anchor) != program or current.count(anchor + fragment) != 1:
        raise ValueError('full_target_inverse')
    if len(current) > 2097152 or max(map(len, current.splitlines())) > 256:
        raise ValueError('original_target_cap')
    ast.parse(current.decode('ascii'), feature_version=(3, 5))
    return current


def parse_private(raw):
    """PC-only two bounded literals; no startup result or close interpretation."""
    if type(raw) is not bytes or len(raw) > 2097152:
        raise ValueError('retained_private_raw_cap')
    text = raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
    output = {}
    for name, prefix, keys in (
            ('cache', CACHE_PREFIX, {'available', 'unknown', 'values', 'prepare_same_object', 'postimport_is_last'}),
            ('collect_error', ERROR_PREFIX, {'available', 'unknown', 'kind', 'errno', 'code', 'trace'})):
        lines = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
        if len(lines) != 1 or len(lines[0]) > 8192:
            raise ValueError('retained_private_one_line')
        tree = ast.parse(lines[0], mode='eval')
        if (not isinstance(tree.body, ast.Dict) or len(tree.body.keys) != len(keys) or
                {ast.literal_eval(key) for key in tree.body.keys} != keys):
            raise ValueError('retained_private_literal_keys')
        value = ast.literal_eval(tree)
        if (type(value) is not dict or set(value) != keys or type(value['available']) is not bool or
                type(value['unknown']) is not bool or value['unknown'] is value['available']):
            raise ValueError('retained_private_shape')
        if value['available'] is False:
            if any(value[key] is not None for key in keys - {'available', 'unknown'}):
                raise ValueError('retained_private_unknown')
        elif name == 'cache':
            numbers = value['values']
            if (type(numbers) is not tuple or len(numbers) != 9 or
                    any(item is not None and (type(item) is not float or not 0 <= item < 1e12) for item in numbers)):
                raise ValueError('retained_private_numbers')
            for flag_name, left, right in (('prepare_same_object', 6, 7), ('postimport_is_last', 4, 5)):
                flag = value[flag_name]
                if numbers[left] is None or numbers[right] is None:
                    if flag is not None:
                        raise ValueError('retained_private_cache_flag')
                elif type(flag) is not bool or flag is True and numbers[left] != numbers[right]:
                    raise ValueError('retained_private_cache_flag')
        else:
            kinds = ('other', 'ValueError', 'TypeError', 'RuntimeError', 'AssertionError', 'OSError',
                     'FileNotFoundError', 'PermissionError', 'TimeoutError', 'InterruptedError', 'BaselineError',
                     'ProcReadError', 'WpaStatusError', 'ClientFileError', 'StartupReadError', 'ReceivePublicationError')
            kind, number, code, trace = value['kind'], value['errno'], value['code'], value['trace']
            if type(kind) is not str or kind not in kinds:
                raise ValueError('retained_private_kind')
            if number is not None and (type(number) is not int or not 0 <= number <= 65535):
                raise ValueError('retained_private_errno')
            if number is not None and kind not in kinds[5:10]:
                raise ValueError('retained_private_errno_kind')
            if code is not None and (type(code) is not str or not 0 < len(code) <= 64 or
                    not all('a' <= c <= 'z' or '0' <= c <= '9' or c == '_' for c in code) or
                    kind not in ('BaselineError', 'ProcReadError', 'WpaStatusError', 'ClientFileError', 'StartupReadError')):
                raise ValueError('retained_private_code')
            modules = ('unknown', 'mta_client_baseline', 'mta_client_proc', 'mta_client_startup_readonly',
                       'mta_client_receive_factory', 'mta_client_wpa_status')
            names = ('unknown', 'collect', '_now', '_open', '_read_file', '_proc', '_actors', '_interfaces',
                     '_status', '_binary_parents', '__init__', '_begin', '_observe', '_observe_body', '_actor_pass',
                     '_originals', '_read', 'read_self', 'read_actor', 'run', 'check_active', 'alias_now',
                     'validate', 'open', 'read', 'stat', 'fstat', '_fail', '_metadata')
            if type(trace) is not tuple or len(trace) > 32:
                raise ValueError('retained_private_trace')
            for row in trace:
                if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or row[0] not in modules or
                        type(row[1]) is not str or row[1] not in names or type(row[2]) is not int or
                        not 1 <= row[2] <= 1000000 or (row[0] == 'unknown') != (row[1] == 'unknown')):
                    raise ValueError('retained_private_trace_row')
        output[name] = value
    return output
