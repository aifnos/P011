"""Pure retained startup-cache projection; no lifecycle, clock, IO or admission.

The target function is inserted only after run_fixed returns. Its fixed numeric
tuple is private evidence, not import-only timing or a resource-close receipt.
"""
import ast
import types


FIELDS = ('startup_boundary_init', 'startup_boundary_private_sources',
          'startup_boundary_wpa', 'startup_boundary_profile',
          'startup_boundary_postimport', 'last', 'prepare_until',
          'original_prepare_until', 'original_until')
PREFIX = 'PRIVATE_STARTUP_CACHED_BOUNDARIES_V1='


def _private_startup_cached_boundaries_v1(retained, session):
    unknown = {'available': False, 'unknown': True, 'values': None,
               'prepare_same_object': None, 'postimport_is_last': None}
    try:
        if type(session) is not types.ModuleType:
            return unknown
        shared = session.__dict__
        session_type = shared.get('FixedSession')
        if (type(session_type) is not type or type(retained) is not session_type or
                retained is not shared.get('_RETAINED')):
            return unknown
        saved = retained.__dict__
        owner, loader = saved.get('owner'), saved.get('loader')
        owner_module = saved.get('owner_module')
        if type(owner_module) is not types.ModuleType:
            return unknown
        owner_namespace = owner_module.__dict__
        owner_type = owner_namespace.get('FixedStateServiceOwner')
        if type(owner_type) is not type or type(owner) is not owner_type:
            return unknown
        owned = owner.__dict__
        if (owned.get('loader') is not loader or
                owned.get('_startup_namespace_original') is not owner_namespace or
                owned.get('_startup_owner_type_original') is not owner_type):
            return unknown
        modules = loader.__dict__.get('modules')
        system = shared.get('sys')
        if type(modules) is not dict or type(system) is not types.ModuleType:
            return unknown
        factory_module = modules.get('mta_client_receive_factory')
        if (type(factory_module) is not types.ModuleType or
                system.modules.get('mta_client_receive_factory') is not factory_module):
            return unknown
        namespace = factory_module.__dict__
        scope_type = namespace.get('_StartupReadScope')
        factory_type = namespace.get('FixedReceiveDeploymentFactory')
        originals, codes = namespace.get('_STARTUP_ALIAS_ORIGINALS'), namespace.get('_STARTUP_ALIAS_CODES')
        if (type(scope_type) is not type or type(factory_type) is not type or
                type(originals) is not tuple or len(originals) != 6 or
                type(codes) is not tuple or len(codes) != 6):
            return unknown
        check = scope_type.__dict__.get('check_active')
        if (type(check) is not types.FunctionType or check is not originals[2] or
                check.__code__ is not codes[2] or check.__globals__ is not namespace):
            return unknown
        error = saved.get('first_error')
        if not isinstance(error, BaseException):
            return unknown
        matches, cursor = [], error.__traceback__
        for unused in range(32):
            if cursor is None:
                break
            frame = cursor.tb_frame
            if frame.f_globals is namespace and frame.f_code is codes[2]:
                value = frame.f_locals.get('self')
                if type(value) is scope_type:
                    matches.append(value)
            cursor = cursor.tb_next
        if cursor is not None or len(matches) != 1:
            return unknown
        scope, factory = matches[0], owned.get('factory')
        if type(factory) is not factory_type:
            return unknown
        cached, made = scope.__dict__, factory.__dict__
        if (type(cached) is not dict or scope is not saved.get('startup_scope') or
                scope is not owned.get('startup_scope') or
                scope is not owned.get('_startup_scope_original') or
                scope is not made.get('_startup_scope') or cached.get('owner') is not owner or
                cached.get('factory') is not factory or cached.get('failure') is not error or
                owned.get('startup_failure') is not error):
            return unknown
        names = ('startup_boundary_init', 'startup_boundary_private_sources',
                 'startup_boundary_wpa', 'startup_boundary_profile',
                 'startup_boundary_postimport', 'last', 'prepare_until',
                 'original_prepare_until', 'original_until')
        if any(name not in cached for name in names):
            return unknown
        before = tuple(cached.get(name) for name in names)
        after = tuple(cached.get(name) for name in names)
        if (scope.__dict__ is not cached or
                any(left is not right for left, right in zip(before, after)) or
                any(value is not None and
                    (type(value) is not float or not 0 <= value < 1e12) for value in before)):
            return unknown
        return {'available': True, 'unknown': False, 'values': before,
                'prepare_same_object': None if before[6] is None or before[7] is None else before[6] is before[7],
                'postimport_is_last': None if before[4] is None or before[5] is None else before[4] is before[5]}
    except BaseException:
        return unknown


def target_fragment(raw):
    text = raw.decode('ascii')
    tree = ast.parse(text, feature_version=(3, 5))
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
            node.name == '_private_startup_cached_boundaries_v1']
    if len(rows) != 1 or rows[0].decorator_list:
        raise ValueError('one_private_projection')
    function = ast.get_source_segment(text, rows[0])
    tail = ("\ntry:\n print('PRIVATE_STARTUP_CACHED_BOUNDARIES_V1='+"
            "repr(_private_startup_cached_boundaries_v1(retained,session)))\n"
            "except BaseException:\n pass\n")
    fragment = (function + tail).encode('ascii')
    if len(fragment) > 16384 or max(map(len, fragment.splitlines())) > 256:
        raise ValueError('fixed_private_projection_cap')
    return fragment


def inject(program, raw):
    anchor = b'retained=session._RETAINED\n'
    fragment = target_fragment(raw)
    if (type(program) is not bytes or program.count(anchor) != 1 or
            b'PRIVATE_STARTUP_CACHED_BOUNDARIES_V1=' in program):
        raise ValueError('after_return_anchor')
    current = program.replace(anchor, anchor + fragment)
    if current.count(anchor + fragment) != 1 or current.replace(anchor + fragment, anchor) != program:
        raise ValueError('complete_private_fragment_inverse')
    if len(current) > 2097152 or max(map(len, current.splitlines())) > 256:
        raise ValueError('original_carrier_cap')
    ast.parse(current.decode('ascii'), feature_version=(3, 5))
    return current


def parse_private(raw):
    """Offline-only bounded literal; never influences startup PASS/close policy."""
    if type(raw) is not bytes or len(raw) > 2097152:
        raise ValueError('private_cache_raw_cap')
    text = raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = [line[len(PREFIX):] for line in text.splitlines() if line.startswith(PREFIX)]
    if len(lines) != 1 or len(lines[0]) > 4096:
        raise ValueError('private_cache_one_line')
    value = ast.literal_eval(lines[0])
    keys = {'available', 'unknown', 'values', 'prepare_same_object', 'postimport_is_last'}
    if (type(value) is not dict or set(value) != keys or
            type(value['available']) is not bool or type(value['unknown']) is not bool):
        raise ValueError('private_cache_shape')
    numbers = value['values']
    if value['available'] is False:
        if (value['unknown'] is not True or numbers is not None or
                value['prepare_same_object'] is not None or value['postimport_is_last'] is not None):
            raise ValueError('private_cache_unknown')
        return value
    if (value['unknown'] is not False or type(numbers) is not tuple or len(numbers) != 9 or
            any(item is not None and (type(item) is not float or not 0 <= item < 1e12)
                for item in numbers)):
        raise ValueError('private_cache_values')
    for name, left, right in (('prepare_same_object', 6, 7), ('postimport_is_last', 4, 5)):
        flag = value[name]
        if numbers[left] is None or numbers[right] is None:
            if flag is not None:
                raise ValueError('private_cache_boolean')
        elif type(flag) is not bool or flag is True and numbers[left] != numbers[right]:
            raise ValueError('private_cache_boolean')
    return value
