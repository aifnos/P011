"""Independent media-mutex receive Startup; default SOURCE, no radio or phone.

Derive the effective authorized prepare20 carrier, not a historical 10-second
graph. Only fixed source bindings, FC9 budget, separate mutex closure and labels
change. Original IO, collector10/STATUS3, diagnostic60+cleanup60, alarm240/HOST250,
COMPONENT/Trial/FAIL gates, strict close/raw sealer and passive projections stay.
The FileCenter companion is retained source, never started by this diagnostic.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_fc_mutex_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_FC_MUTEX_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_FC_MUTEX_V1_STARTUP.cmd')
MOTHER = ('host/device_receive_startup_20s_v1_check.py', 9070,
          '378784c34c014581aa9719dad379dd825052ca547abbce5fe8802b0e113798b5')
DEFINITIONS = ('host/formal_receive_fc_mutex_v1_definitions.py', 574969,
               '4fce39627676c7f359dfd031ce8edb19e232c1a5981806895014829a4fbb8dfd')
GENERATION = ('candidate/receive-fc-mutex-graph-v1/graph-generation.json', 4365,
              '57d30394018a7fd5f149193ea13a01e08e28c220a9429759e9e61b938d450418')
GRAPH_RECIPE = ('candidate/receive-fc-mutex-graph-v1/generate_graph.py', 43011,
                '98ad07f8dabe99fdfdca601da63138dc6bbd62fcf7dcbc277c65a648162534c8')
MUTEX_COMPANION = ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py',
                   35198, '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca')
FLAT_COUNT = 319
PAYLOAD_BYTES = 4193768
FILECENTER_BYTES = 115400
BUSINESS_CLOSURE_COUNT = 1
MUTEX_BUSINESS_CLOSURE_COUNT = 1
ROOT_NAME = 'p011-mta-rx-mlock1-v001'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def module_without_entry(raw, path, name):
    tree = ast.parse(raw.decode('ascii'))
    need(isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test) == ast.dump(ast.parse(
             "__name__ == '__main__'", mode='eval').body), 'fixed_entry_guard')
    tree.body.pop()
    module = types.ModuleType(name)
    module.__file__ = str(BASE / path)
    exec(compile(tree, module.__file__, 'exec'), module.__dict__)
    return module


def derive(raw):
    """Finite HOST binding/label edits with complete byte and position inverse."""
    changes, current = [], raw

    def change(before, after, count=1):
        nonlocal current
        before, after = before.encode('ascii'), after.encode('ascii')
        need(before != after and current.count(before) == count and not current.count(after),
             'mutex_startup_finite_forward')
        current = current.replace(before, after)
        changes.append((before, after, count))

    change("SELF = 'host/device_receive_startup_20s_v1_check.py'", 'SELF = ' + repr(SELF))
    change("CMDS = ('HOST_MTA_RECEIVE_STARTUP_20S_V1_CHECK.cmd', 'TEST_MTA_RECEIVE_STARTUP_20S_V1.cmd')",
           'CMDS = ' + repr(CMDS))
    change("DEFINITIONS = ('host/formal_receive_startup_20s_v1_definitions.py', 297239, '49a56e7e809f2f515ca66735a38adf68d162aea1697e8d6a17cd74d0f68c61ca')",
           'DEFINITIONS = ' + repr(DEFINITIONS))
    change("ROOT_NAME = 'p011-mta-rx-prep20-v001'", 'ROOT_NAME = ' + repr(ROOT_NAME))
    change('len(definitions.ORIGIN_SOURCE_PINS) == 304',
           'len(definitions.ORIGIN_SOURCE_PINS) == ' + str(FLAT_COUNT))
    change('sum(row[2] for row in fc_rows) == 113832 <= 131072',
           'sum(row[2] for row in fc_rows) == ' + str(FILECENTER_BYTES) + ' <= 131072')
    change('definitions.BUSINESS_CLOSURE_COUNT == 1 and',
           'definitions.BUSINESS_CLOSURE_COUNT == ' + str(BUSINESS_CLOSURE_COUNT) + ' and\n'
           '             definitions.MUTEX_BUSINESS_CLOSURE_COUNT == ' + str(MUTEX_BUSINESS_CLOSURE_COUNT) + ' and\n'
           '             tuple(definitions.MUTEX_EXPECTED[\'candidate\']) == ' + repr(MUTEX_COMPANION) + ' and')
    change("'new_fc_http_cap_mechanical_and_source_closures'",
           "'new_fc_mutex_retained_prepare20_and_separate_source_closures'")
    change('filecenter_sources=9, filecenter_bytes=113832, flat_origin_pins=304,',
           'filecenter_sources=9, filecenter_bytes=' + str(FILECENTER_BYTES) + ', flat_origin_pins=' + str(FLAT_COUNT) + ',')
    change('mechanical_closures=6, filecenter_http_business_sources=2, profile_cache_business_methods=1,',
           'mechanical_closures=6, filecenter_http_business_sources=2, profile_cache_business_methods=1,\n'
           '            retained_prepare20_business_closures=1, filecenter_mutex_business_sources=1,\n'
           '            filecenter_media_lock_deadline_device_verified=False,')
    change("'receive-startup-20s-v1-'", "'receive-fc-mutex-v1-startup-'")
    change("label = 'receive-startup-20s-v1'", "label = 'receive-fc-mutex-v1-startup'")
    change('p011-receive-startup-20s-v1', 'p011-receive-fc-mutex-v1-startup', 2)
    change('        fixed(MOTHER)\n', '        fixed(MOTHER)\n        fixed(PROFILE_RECIPE)\n')
    change("b'Authorized independent prepare10-to20 constant only; cached DATA and prior Owner/Scope/FC closures retained.\\n'",
           "b'Retained authorized prepare20 and cached DATA; new separate media-mutex closure1, mechanical6.\\n'")
    change("b'Actual75/4193768 retains original4MiB cap (536 spare); FC9/113832 retains separate131072 cap.\\n'",
           "b'Actual75/4193768 retains original4MiB cap (536 spare); FC9/115400 retains separate131072 cap.\\n'")
    restored = current
    for before, after, count in reversed(changes):
        need(restored.count(after) == count, 'mutex_startup_finite_reverse')
        restored = restored.replace(after, before)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'mutex_startup_complete_host_inverse')
    old = {node.name: ast.get_source_segment(raw.decode('ascii'), node)
           for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new = {node.name: ast.get_source_segment(current.decode('ascii'), node)
           for node in ast.parse(current).body if isinstance(node, ast.FunctionDef)}
    need(set(old) == set(new) and all(old[name] == new[name] for name in old if name != 'main') and
         not any(isinstance(node, ast.If) for node in ast.parse(current).body),
         'mutex_startup_original_helpers_byte_exact_no_entry')
    return current


def prepare():
    pins = (MOTHER, DEFINITIONS, GENERATION, GRAPH_RECIPE, MUTEX_COMPANION)
    need(all(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and 0 < pin[1] <= 2097152 and type(pin[2]) is str and
             len(pin[2]) == 64 and all(char in '0123456789abcdef' for char in pin[2]) for pin in pins) and
         FLAT_COUNT == 319 and PAYLOAD_BYTES == 4193768 and FILECENTER_BYTES == 115400 and
         BUSINESS_CLOSURE_COUNT == MUTEX_BUSINESS_CLOSURE_COUNT == 1,
         'mutex_startup_graph_bindings_sealed')
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'fixed_mutex_startup20_parent')
    parent = module_without_entry(raw, MOTHER[0], 'fixed_mutex_startup20_parent_no_main')
    origin = parent.prepare()
    need(origin.__dict__['HOST_RAW'] and origin.SELF == MOTHER[0] and
         origin.ROOT_NAME == 'p011-mta-rx-prep20-v001' and origin.PAYLOAD_BYTES == PAYLOAD_BYTES,
         'mutex_startup_effective_prepare20_parent')
    selected = derive(origin.HOST_RAW)
    driver = types.ModuleType('fixed_receive_fc_mutex_v1_startup_host')
    driver.__file__ = str(BASE / SELF)
    exec(compile(selected, driver.__file__, 'exec'), driver.__dict__)
    driver.__dict__.update(MOTHER=MOTHER, PROFILE_RECIPE=origin.MOTHER,
        FC_RECIPE=origin.FC_RECIPE, CARRIER=origin.CARRIER, PROJECTION=origin.PROJECTION,
        SCOPE_RECIPE=origin.SCOPE_RECIPE, PROFILE_PROJECTION=origin.PROFILE_PROJECTION,
        GENERATION=GENERATION, GRAPH_RECIPE=GRAPH_RECIPE,
        SEED_GENERATOR=origin.SEED_GENERATOR, SEED_DELTA=origin.SEED_DELTA, SEED_FACTORY=origin.SEED_FACTORY,
        HOST_RAW=selected, attach_projection=origin.attach_projection,
        observe_profile_cache=origin.observe_profile_cache)
    return driver


if __name__ == '__main__':
    raise SystemExit(prepare().main())
