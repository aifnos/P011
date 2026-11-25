"""Private cached-clock DATA for the retained real StartupReadScope only.

The V2 context function is copied byte-for-byte. Read profile_cache from the
held scope dictionary; do not call a clock, IO, status, close or admission API.
Six existing attempt.last values are cached boundaries, not precise function
wall times. A prefix of length zero through six means later stages were not
reached; a missing cache or rejected identity remains unknown, not a PASS gate.
The original V2 projection, COMPONENT, TRIAL and all startup results stay intact.
"""
import ast
import types

PREFIX = 'PRIVATE_STARTUP_PROFILE_CACHE_V1='
LABELS = ('python', 'proc', 'daemon', 'namespace', 'endpoint', 'continuity')
FUNCTIONS = ('_private_startup_retained_context_v2', '_private_startup_profile_cache_v1')


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


def _private_startup_profile_cache_v1(retained, session):
    unknown = dict(available=False, unknown=True, labels=None, values=None, cached_count=None)
    try:
        context = _private_startup_retained_context_v2(retained, session)
        if context is None:
            return unknown
        cached, scope = context[2], context[6]
        before = cached.get('profile_cache')
        after = cached.get('profile_cache')
        if (scope.__dict__ is not cached or before is not after or
                type(before) is not tuple or len(before) > 6 or
                any(type(value) is not float or not 0 <= value < 1e12 for value in before)):
            return unknown
        labels = ('python', 'proc', 'daemon', 'namespace', 'endpoint', 'continuity')
        return dict(available=True, unknown=False, labels=labels,
                    values=before + (None,) * (6 - len(before)), cached_count=len(before))
    except BaseException:
        return unknown


def target_fragment(raw):
    text = raw.decode('ascii')
    tree = ast.parse(text, feature_version=(3, 5))
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    if tuple(node.name for node in rows) != FUNCTIONS or any(node.decorator_list for node in rows):
        raise ValueError('profile_cache_two_target_functions')
    functions = '\n\n'.join(ast.get_source_segment(text, node) for node in rows)
    tail = ("\ntry:\n print('PRIVATE_STARTUP_PROFILE_CACHE_V1='+"
            "repr(_private_startup_profile_cache_v1(retained,session)))\n"
            "except BaseException:\n pass\n")
    fragment = (functions + tail).encode('ascii')
    if len(fragment) > 16384 or max(map(len, fragment.splitlines())) > 256:
        raise ValueError('profile_cache_private_fragment_cap')
    return fragment


def inject(program, raw):
    """Insert DATA after retained assignment; preserve every original byte."""
    anchor = b'retained=session._RETAINED\n'
    fragment = target_fragment(raw)
    if type(program) is not bytes or program.count(anchor) != 1 or PREFIX.encode('ascii') in program:
        raise ValueError('profile_cache_one_after_return_anchor')
    current = program.replace(anchor, anchor + fragment, 1)
    if current.replace(anchor + fragment, anchor, 1) != program or current.count(anchor + fragment) != 1:
        raise ValueError('profile_cache_full_target_inverse')
    if len(current) > 2097152 or max(map(len, current.splitlines())) > 256:
        raise ValueError('profile_cache_original_target_cap')
    ast.parse(current.decode('ascii'), feature_version=(3, 5))
    return current


def parse_private(raw):
    """PC-only strict DATA; cached boundaries do not certify precise wall time."""
    if type(raw) is not bytes or len(raw) > 2097152:
        raise ValueError('profile_cache_private_raw_cap')
    text = raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = [line[len(PREFIX):] for line in text.splitlines() if line.startswith(PREFIX)]
    if len(lines) != 1 or len(lines[0]) > 2048:
        raise ValueError('profile_cache_private_one_line')
    tree = ast.parse(lines[0], mode='eval')
    keys = {'available', 'unknown', 'labels', 'values', 'cached_count'}
    if (not isinstance(tree.body, ast.Dict) or len(tree.body.keys) != len(keys) or
            {ast.literal_eval(key) for key in tree.body.keys} != keys):
        raise ValueError('profile_cache_private_literal_keys')
    value = ast.literal_eval(tree)
    if (type(value) is not dict or set(value) != keys or type(value['available']) is not bool or
            type(value['unknown']) is not bool or value['unknown'] is value['available']):
        raise ValueError('profile_cache_private_shape')
    if value['available'] is False:
        if any(value[name] is not None for name in ('labels', 'values', 'cached_count')):
            raise ValueError('profile_cache_private_unknown')
        return value
    labels, numbers, count = value['labels'], value['values'], value['cached_count']
    if (type(labels) is not tuple or labels != LABELS or any(type(label) is not str for label in labels) or
            type(numbers) is not tuple or len(numbers) != 6 or type(count) is not int or not 0 <= count <= 6):
        raise ValueError('profile_cache_private_cache_shape')
    if (any(type(number) is not float or not 0 <= number < 1e12 for number in numbers[:count]) or
            any(number is not None for number in numbers[count:])):
        raise ValueError('profile_cache_private_cached_prefix')
    return value
