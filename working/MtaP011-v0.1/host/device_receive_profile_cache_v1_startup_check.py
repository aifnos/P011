"""Profile-cache-only Startup diagnostic; default SOURCE, no radio admission.

The measured FC HTTP-cap entry is prepared without its main. Its effective
HOST source receives finite graph bindings plus a pure retained-cache report.
Original Startup10, 60+60, alarm240/HOST250 and closed policy remain unchanged.
The profile projection never adds a clock/IO or changes COMPONENT/Trial/PASS.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_profile_cache_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROFILE_CACHE_V1_STARTUP.cmd')
MOTHER = ('host/device_receive_fc_http_cap_v1_startup_check.py', 10817,
          '19528721756c26c3688fe484942c66c9312e043d8c323960e18e5b2d12616e10')
SCOPE_RECIPE = ('host/device_receive_scope_dispatch_v1_startup_check.py', 8334,
                'f783bda303a2975dc09a0beb67daac3fd9879230517418ea107f1ddce43d915e')
# These fixed bindings are sealed after the one exclusive graph publication.
DEFINITIONS = ('host/formal_receive_profile_cache_v1_definitions.py', 276517,
               'fc1327b17f4124e286b967b3246f59c69458b803834efb34fd56246350bb5043')
GENERATION = ('candidate/receive-profile-cache-graph-v1/graph-generation.json', 3728,
              'c2da0bbbb53fae4768a3ded155619d03935f2aac4c31582b701cb786a39c8e91')
PROFILE_PROJECTION = ('host/receive_profile_cache_v1_projection.py', 8250,
                      '5bf3b440ccbc15fac60cae98cac9cf0f16b041ad73594ef37633962731eaedc1')
FLAT_COUNT = 289
PAYLOAD_BYTES = 4193768
ROOT_NAME = 'p011-mta-rx-pfcache-v01'


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
    changes, current = [], raw

    def change(before, after, count=1):
        nonlocal current
        before, after = before.encode('ascii'), after.encode('ascii')
        need(before != after and current.count(before) == count and not current.count(after),
             'profile_finite_forward')
        current = current.replace(before, after)
        changes.append((before, after, count))

    change("SELF = 'host/device_receive_fc_http_cap_v1_startup_check.py'", 'SELF = ' + repr(SELF))
    change("CMDS = ('HOST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP.cmd')",
           'CMDS = ' + repr(CMDS))
    change("DEFINITIONS = ('host/formal_receive_fc_http_cap_v1_definitions.py', 169842, 'c43f342a7c7ccafe5e2780de7f4068bdfe84195579b5f1c6e970d78ad19abfc2')",
           'DEFINITIONS = ' + repr(DEFINITIONS))
    change("ROOT_NAME = 'p011-mta-rx-fccap-v0001'", 'ROOT_NAME = ' + repr(ROOT_NAME))
    change('PAYLOAD_BYTES = 4193464', 'PAYLOAD_BYTES = ' + str(PAYLOAD_BYTES))
    change('len(definitions.ORIGIN_SOURCE_PINS) == 274',
           'len(definitions.ORIGIN_SOURCE_PINS) == ' + str(FLAT_COUNT))
    change('definitions.BUSINESS_CLOSURE_COUNT == 2 and',
           'definitions.BUSINESS_CLOSURE_COUNT == 1 and')
    change('payload_remaining_bytes=840,',
           'payload_remaining_bytes=' + str(4194304 - PAYLOAD_BYTES) + ',')
    change('flat_origin_pins=274,', 'flat_origin_pins=' + str(FLAT_COUNT) + ',')
    change('mechanical_closures=6, filecenter_http_business_sources=2,',
           'mechanical_closures=6, filecenter_http_business_sources=2, profile_cache_business_methods=1,')
    change("'receive-fc-http-cap-v1-startup-'", "'receive-profile-cache-v1-startup-'")
    change("label = 'receive-fc-http-cap-v1-startup'", "label = 'receive-profile-cache-v1-startup'")
    change('p011-receive-fc-http-cap-v1-startup', 'p011-receive-profile-cache-v1-startup', 2)
    change('        projection_raw = fixed(PROJECTION)\n',
           '        projection_raw = fixed(PROJECTION)\n'
           '        profile_raw = fixed(PROFILE_PROJECTION)\n'
           '        fixed(GENERATION)\n')
    change('        fixed(MOTHER)\n',
           '        fixed(MOTHER)\n        fixed(SCOPE_RECIPE)\n')
    change('        pure = attach_projection(pure, projection_raw)\n',
           '        pure = attach_projection(pure, projection_raw, profile_raw)\n')
    change("                    report['remote_status_known'] = len(exits) == 1\n",
           "                    report['remote_status_known'] = len(exits) == 1\n"
           "                    report['profile_cache_data'] = observe_profile_cache(raw)\n")
    change("b'Actual flat274 provenance, 6 mechanical closures and two FC HTTP business sources; inherited Owner/Scope deltas retained.\\n'",
           "b'Independent profile cached DATA only; six mechanical closures and prior Owner/Scope/FC sources retained.\\n'")
    change("b'Actual75/4193464 retains original4MiB cap (840 spare); FC9/113832 retains separate131072 cap.\\n'",
           "b'Actual75/" + str(PAYLOAD_BYTES) + " retains original4MiB cap (" +
           str(4194304 - PAYLOAD_BYTES) + " spare); FC9/113832 retains separate131072 cap.\\n'")
    restored = current
    for before, after, count in reversed(changes):
        need(restored.count(after) == count, 'profile_finite_reverse')
        restored = restored.replace(after, before)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'profile_complete_host_inverse')
    old = {node.name: ast.get_source_segment(raw.decode('ascii'), node)
           for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new = {node.name: ast.get_source_segment(current.decode('ascii'), node)
           for node in ast.parse(current).body if isinstance(node, ast.FunctionDef)}
    need(set(old) == set(new) and all(old[name] == new[name] for name in old if name != 'main'),
         'profile_original_host_helpers_byte_exact')
    return current


def prepare():
    need(all(type(pin) is tuple and len(pin) == 3 for pin in
             (DEFINITIONS, GENERATION, PROFILE_PROJECTION)) and
         type(FLAT_COUNT) is int and type(PAYLOAD_BYTES) is int and
         0 < PAYLOAD_BYTES <= 4194304, 'profile_graph_bindings_not_sealed')
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'fixed_profile_host_mother')
    parent = module_without_entry(raw, MOTHER[0], 'fixed_profile_host_pure_parent')
    origin = parent.prepare()
    need(origin.__dict__['HOST_RAW'] and origin.SELF == MOTHER[0], 'profile_effective_parent')
    selected = derive(origin.HOST_RAW)
    driver = types.ModuleType('fixed_profile_cache_v1_host')
    driver.__file__ = str(BASE / SELF)
    exec(compile(selected, driver.__file__, 'exec'), driver.__dict__)
    original_attach = parent.attach_projection
    profile_projection = [None]

    def projection_module(profile_raw):
        need((len(profile_raw), digest(profile_raw)) == PROFILE_PROJECTION[1:], 'profile_projection_pin')
        value = types.ModuleType('fixed_profile_cached_data_projection')
        exec(compile(profile_raw, str(BASE / PROFILE_PROJECTION[0]), 'exec'), value.__dict__)
        return value

    def observe_profile_cache(raw):
        # Diagnostic DATA only: an absent/malformed record cannot change PASS.
        try:
            value = profile_projection[0]
            need(type(value) is types.ModuleType, 'profile_projection_not_attached')
            return value.parse_private(raw)
        except BaseException as failure:
            return dict(available=False, unknown=True, labels=None, values=None,
                        cached_count=None, diagnostic_error=type(failure).__name__)

    def attach(pure, retained_raw, profile_raw):
        value = projection_module(profile_raw)
        profile_projection[0] = value
        original_attach(pure, retained_raw)
        make = pure.make_source

        def make_source(definitions, helpers, inputs, payload):
            original, program = make(definitions, helpers, inputs, payload)
            return original, value.inject(program, profile_raw)

        pure.make_source = make_source
        return pure

    driver.__dict__.update(MOTHER=MOTHER, CARRIER=parent.CARRIER, PROJECTION=parent.PROJECTION,
                          SCOPE_RECIPE=SCOPE_RECIPE,
                          PROFILE_PROJECTION=PROFILE_PROJECTION, GENERATION=GENERATION,
                          HOST_RAW=selected, attach_projection=attach,
                          observe_profile_cache=observe_profile_cache)
    return driver


if __name__ == '__main__':
    raise SystemExit(prepare().main())
