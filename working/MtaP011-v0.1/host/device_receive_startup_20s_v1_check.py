"""Independent authorized prepare20 Startup check; default SOURCE, never RF.

Only the new graph binding and truthful prepare20/collector10 labels derive
from the measured profile-cache carrier. The original six cached DATA values,
retained V2 projection, raw/sealer, COMPONENT/Trial/FAIL gates, collector10,
STATUS3, activity60+cleanup60, alarm240/HOST250 and close policy are unchanged.
Unsealed graph pins refuse preparation before a result directory or device.
No old main, builder, test, phone, BLE or Wi-Fi action is invoked here.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_startup_20s_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_STARTUP_20S_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_STARTUP_20S_V1.cmd')
MOTHER = ('host/device_receive_profile_cache_v1_startup_check.py', 9043,
          '029f69095d53d1adf6a3d1933f8e93ba75b3adc7b3cef14e613c81044f7930bb')
FC_RECIPE = ('host/device_receive_fc_http_cap_v1_startup_check.py', 10817,
             '19528721756c26c3688fe484942c66c9312e043d8c323960e18e5b2d12616e10')
SEED_GENERATOR = ('candidate/receive-startup-20s-v1/generate_seed.py', 8560,
                  '313186ad15e4a6eb6c8d148c08a99044c572f7bb105b2fd8ade774214e11f84c')
SEED_DELTA = ('candidate/receive-startup-20s-v1/exactsource-delta.json', 1823,
              '935415b58c9ee53ac860398bd89819eac6a1a9e8492cb9ad9bdd7b81823c4a3f')
SEED_FACTORY = ('candidate/receive-startup-20s-v1/runtime/mta_client_receive_factory.py', 99675,
                '32784fee80f5e74d8e49e4a517e5dc5d45f297c0ad2f5bad42b343b81872da4d')
# Actual exclusive graph publication: 11 new outputs, 304 flat sources.
DEFINITIONS = ('host/formal_receive_startup_20s_v1_definitions.py', 297239,
               '49a56e7e809f2f515ca66735a38adf68d162aea1697e8d6a17cd74d0f68c61ca')
GENERATION = ('candidate/receive-startup-20s-graph-v1/graph-generation.json', 4018,
              '050b47d1ef6e28035f84d446a098279785fd55cda487cd0c514eb25c575dc563')
GRAPH_RECIPE = ('candidate/receive-startup-20s-graph-v1/generate_graph.py', 41819,
                'e3b690ff769187c48d87448198371d8025ed8fcdd9ae78678f8e17cf56e338d8')
FLAT_COUNT = 304
PAYLOAD_BYTES = 4193768
BUSINESS_CLOSURE_COUNT = 1
ROOT_NAME = 'p011-mta-rx-prep20-v001'


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
    """Finite binding/report edits; all original non-main helper bytes exact."""
    changes, current = [], raw

    def change(before, after, count=1):
        nonlocal current
        before, after = before.encode('ascii'), after.encode('ascii')
        need(current.count(before) == count, 'prepare20_finite_old_anchor')
        if before == after:
            return
        need(not current.count(after), 'prepare20_finite_new_anchor')
        current = current.replace(before, after)
        changes.append((before, after, count))

    change("SELF = 'host/device_receive_profile_cache_v1_startup_check.py'", 'SELF = ' + repr(SELF))
    change("CMDS = ('HOST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP.cmd')",
           'CMDS = ' + repr(CMDS))
    change("DEFINITIONS = ('host/formal_receive_profile_cache_v1_definitions.py', 276517, 'fc1327b17f4124e286b967b3246f59c69458b803834efb34fd56246350bb5043')",
           'DEFINITIONS = ' + repr(DEFINITIONS))
    change("ROOT_NAME = 'p011-mta-rx-pfcache-v01'", 'ROOT_NAME = ' + repr(ROOT_NAME))
    change('PAYLOAD_BYTES = 4193768', 'PAYLOAD_BYTES = ' + str(PAYLOAD_BYTES))
    change('len(definitions.ORIGIN_SOURCE_PINS) == 289',
           'len(definitions.ORIGIN_SOURCE_PINS) == ' + str(FLAT_COUNT))
    change('definitions.BUSINESS_CLOSURE_COUNT == 1 and',
           'definitions.BUSINESS_CLOSURE_COUNT == ' + str(BUSINESS_CLOSURE_COUNT) + ' and')
    change('payload_remaining_bytes=536,',
           'payload_remaining_bytes=' + str(4194304 - PAYLOAD_BYTES) + ',')
    change('flat_origin_pins=289,', 'flat_origin_pins=' + str(FLAT_COUNT) + ',')
    change('original_activity_seconds=60, original_cleanup_seconds=60, startup_seconds=10,',
           'original_activity_seconds=60, original_cleanup_seconds=60, startup_seconds=10,\n'
           '        prepare_seconds=20, collector_seconds=10, status_cap_seconds=3,\n'
           '        independent_prepare_candidate=True, authorized_prepare_constant_delta_count=1,')
    change("'receive-profile-cache-v1-startup-'", "'receive-startup-20s-v1-'")
    change("label = 'receive-profile-cache-v1-startup'", "label = 'receive-startup-20s-v1'")
    change('p011-receive-profile-cache-v1-startup', 'p011-receive-startup-20s-v1', 2)
    change('        fixed(MOTHER)\n',
           '        fixed(MOTHER)\n'
           '        fixed(FC_RECIPE)\n'
           '        fixed(SEED_GENERATOR)\n'
           '        fixed(SEED_DELTA)\n'
           '        fixed(SEED_FACTORY)\n'
           '        fixed(GRAPH_RECIPE)\n')
    change("b'then run original diagnostic60+cleanup60, Startup10, alarm240/host250 and closed policy.\\n'",
           "b'then run independent prepare20/collector10/STATUS3, original60+cleanup60 and alarm240/host250.\\n'")
    change("b'Independent profile cached DATA only; six mechanical closures and prior Owner/Scope/FC sources retained.\\n'",
           "b'Authorized independent prepare10-to20 constant only; cached DATA and prior Owner/Scope/FC closures retained.\\n'")
    change("b'Actual75/4193768 retains original4MiB cap (536 spare); FC9/113832 retains separate131072 cap.\\n'",
           "b'Actual75/" + str(PAYLOAD_BYTES) + " retains original4MiB cap (" +
           str(4194304 - PAYLOAD_BYTES) + " spare); FC9/113832 retains separate131072 cap.\\n'")
    restored = current
    for before, after, count in reversed(changes):
        need(restored.count(after) == count, 'prepare20_finite_reverse')
        restored = restored.replace(after, before)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'prepare20_complete_host_inverse')
    old = {node.name: ast.get_source_segment(raw.decode('ascii'), node)
           for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new = {node.name: ast.get_source_segment(current.decode('ascii'), node)
           for node in ast.parse(current).body if isinstance(node, ast.FunctionDef)}
    need(set(old) == set(new) and all(old[name] == new[name] for name in old if name != 'main') and
         not any(isinstance(node, ast.If) for node in ast.parse(current).body),
         'prepare20_original_host_helpers_byte_exact_no_entry')
    return current


def prepare():
    pins = (DEFINITIONS, GENERATION, GRAPH_RECIPE, MOTHER, FC_RECIPE,
            SEED_GENERATOR, SEED_DELTA, SEED_FACTORY)
    need(all(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and 0 < pin[1] <= 2097152 and
             type(pin[2]) is str and len(pin[2]) == 64 and
             all(char in '0123456789abcdef' for char in pin[2]) for pin in pins) and
         type(FLAT_COUNT) is int and FLAT_COUNT > 289 and
         type(PAYLOAD_BYTES) is int and 0 < PAYLOAD_BYTES <= 4194304 and
         type(BUSINESS_CLOSURE_COUNT) is int and BUSINESS_CLOSURE_COUNT > 0,
         'prepare20_graph_bindings_not_sealed')
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'fixed_prepare20_host_mother')
    parent = module_without_entry(raw, MOTHER[0], 'fixed_prepare20_host_pure_parent')
    need(parent.MOTHER == FC_RECIPE, 'prepare20_original_fc_recipe')
    origin = parent.prepare()
    need(origin.__dict__['HOST_RAW'] and origin.SELF == MOTHER[0], 'prepare20_effective_parent')
    selected = derive(origin.HOST_RAW)
    driver = types.ModuleType('fixed_startup_20s_v1_host')
    driver.__file__ = str(BASE / SELF)
    exec(compile(selected, driver.__file__, 'exec'), driver.__dict__)
    driver.__dict__.update(MOTHER=MOTHER, FC_RECIPE=FC_RECIPE,
        CARRIER=origin.CARRIER, PROJECTION=origin.PROJECTION, SCOPE_RECIPE=origin.SCOPE_RECIPE,
        PROFILE_PROJECTION=origin.PROFILE_PROJECTION, GENERATION=GENERATION,
        GRAPH_RECIPE=GRAPH_RECIPE, SEED_GENERATOR=SEED_GENERATOR,
        SEED_DELTA=SEED_DELTA, SEED_FACTORY=SEED_FACTORY,
        HOST_RAW=selected, attach_projection=origin.attach_projection,
        observe_profile_cache=origin.observe_profile_cache)
    return driver


if __name__ == '__main__':
    raise SystemExit(prepare().main())
