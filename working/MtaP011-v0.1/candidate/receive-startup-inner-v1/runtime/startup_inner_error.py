"""Passive projection of a retained BaselineCollector.collect local error.

No exception, frame, actor, source definition or lifetime is modified. Raw
exception args/locals and private identifiers are never returned.
"""
import re
import types


def extract_inner(outer, collect_function, collector, namespaces):
    if (not isinstance(outer, BaseException) or type(collect_function) is not types.FunctionType or
            type(namespaces) is not dict or
            collect_function.__globals__ is not namespaces.get('mta_client_baseline')):
        return None
    cursor = outer.__traceback__
    for unused in range(32):
        if cursor is None:
            return None
        frame = cursor.tb_frame
        if (frame.f_code is collect_function.__code__ and
                frame.f_globals is collect_function.__globals__ and
                frame.f_locals.get('self') is collector):
            inner = frame.f_locals.get('error')
            if not isinstance(inner, BaseException) or inner is outer:
                return None
            kind = type(inner).__name__
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', kind) is None:
                kind = 'unclassified'
            number = getattr(inner, 'errno', None)
            number = number if type(number) is int and 1 <= number <= 4095 else None
            frames = []
            original = inner.__traceback__
            for ignored in range(32):
                if original is None:
                    break
                actual = original.tb_frame
                module = actual.f_globals.get('__name__')
                name = actual.f_code.co_name
                line = original.tb_lineno
                if (type(module) is str and actual.f_globals is namespaces.get(module) and
                        type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', name) is not None and
                        type(line) is int and 1 <= line <= 1000000):
                    frames.append((module, name, line))
                original = original.tb_next
            return dict(kind=kind, errno=number, trace=tuple(frames))
        cursor = cursor.tb_next
    return None


def project_original(component):
    """Require the original Scope/Collection/collector before reading a frame."""
    try:
        owner = component.owner
        scope = owner.startup_scope
        if scope is None or scope is not owner._startup_scope_original:
            return dict(reason='not_available', entries=())
        ticket = scope.collector_ticket
        module = component.loader.modules['mta_client_startup_readonly']
        collection = ticket['returned']
        if (type(ticket) is not dict or ticket['creator'] is not module.StartupCollection or
                type(collection) is not module.StartupCollection or collection.scope is not scope or
                collection.modules is not collection._modules_original or
                collection.modules is not scope.private_modules):
            return dict(reason='unknown', entries=())
        baseline = collection.modules['mta_client_baseline']
        collector = collection.collector
        function = baseline.BaselineCollector.collect
        if (type(baseline) is not types.ModuleType or collector is None or
                collector is not collection._collector_original or
                type(collector) is not collection._native_class or
                collection._definitions[0] is not baseline.BaselineCollector or
                collection._definitions[1] is not function or function.__globals__ is not baseline.__dict__):
            return dict(reason='unknown', entries=())
        namespaces = dict((name, value.__dict__) for name, value in collection.modules.items()
                          if type(value) is types.ModuleType)
        namespaces['mta_client_startup_readonly'] = module.__dict__
        entries, seen = [], []
        for error in tuple(component.failures) + (collection.failure, owner.startup_failure):
            if not isinstance(error, BaseException) or any(error is item for item in seen):
                continue
            seen.append(error)
            row = extract_inner(error, function, collector, namespaces)
            if row is not None and row not in entries:
                entries.append(row)
        return dict(reason='observed' if entries else 'not_available', entries=tuple(entries[:8]))
    except BaseException:
        # Diagnostic absence never clears or replaces any original failure.
        return dict(reason='unknown', entries=())
