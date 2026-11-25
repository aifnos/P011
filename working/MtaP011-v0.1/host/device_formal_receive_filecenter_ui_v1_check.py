"""Fixed true Receiver plus FileCenter UI; SOURCE default, no automatic RF.

The new main narrowly adapts the proven Receiver carrier algorithm for the
fixed19 asset inventory and independent FC9 memory inputs. All original39
Receiver observations remain required; seven real FileCenter facts strengthen
completion. Explicit --stage-device is files only; --ui-smoke is launched+20s
under original600+60. No historical main/suite/builder runs or fake credentials.
"""
import ast
import base64
import copy
import hashlib
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v1_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V1_CHECK.cmd',
        'STAGE_MTA_FORMAL_RECEIVE_FILECENTER_UI_V1_ASSETS.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V1.cmd')
ORIGIN = ('host/device_formal_receive_ui_v1_check.py', 24136,
          'f72c802ab8fbec8cc1e0b228ed8c779dd69752b9fa279ad1b966558c4d095857')
DIAGNOSTIC = ('host/device_formal_receive_ui_v3_check.py', 9924,
              '102915d0061ba8834cd40c0a519124cc42e5902f28adaab9516d857d94d44b90')
NATIVE = ('host/device_receive_filecenter_assets_v1_check.py', 46084,
          'cd5dc6cdf074a71d5309b1444e37c2fa0489c0fd5ca62e9fba9860eaa9f8c5e9')
# Final immutable build/worker/composition identities are sealed by ROOT.
SESSION = '1293b528d39ff32746dbe196'
BUNDLE = 'out/mta-ui-receive-filecenter-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
WORKER = ('candidate/formal-receive-filecenter-ui-v1/runtime/ui_session.py', 91414,
          '06eae9cb05ffc2c9fa04bfe3f5101e6d8b8bb8b0fcf9712bb3d7983f55048b9e')
VALIDATOR = ('candidate/formal-receive-filecenter-ui-v1/runtime/ui_assets.py', 12518,
             '358d69056955b85458acbabeae28dc909a8ea1e0870862db99633566bfe6cc39')
DEFINITIONS = ('host/formal_receive_filecenter_v1_definitions.py', 13159,
               '632d12d5d4f4cb7f30df634ec3e32b22ca4eadfb2dc03e3c2867cce0ff908414')
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 4241,
                  'f7fb2da3339c3eb04542f04881c67184c8e69e2ecb7589b01919b0dd2aae0157')
ASSET_BYTES = 4180813
PAYLOAD_BYTES = 4157625
FC_ROWS = ()
FILECENTER_FIELDS = ('filecenter_constructed', 'filecenter_credentials_issued',
                    'filecenter_close_called', 'filecenter_closed',
                    'filecenter_http_observed', 'filecenter_guardian_bound',
                    'filecenter_audio_settled')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def shape(node):
    return ast.dump(node, include_attributes=False)


def expression(raw):
    return ast.parse(raw, mode='eval').body


def set_child(parent, field, value):
    if type(parent) is list:
        parent[field] = value
    else:
        setattr(parent, field, value)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'fixed_source_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    value = types.ModuleType(name)
    value.__file__ = str(BASE / pin[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value, raw


def asset_helper(helper, validator):
    """Original FC19 algorithms, only fixed asset identity literals differ."""
    helper.SESSION, helper.BUNDLE, helper.REMOTE = SESSION, BUNDLE, REMOTE
    helper.VALIDATOR = VALIDATOR
    helper.PINS = validator.PINS
    helper.MANIFEST = ('SOURCE.sha256',) + validator.MANIFEST_PIN
    helper.ASSET_PINS = helper.PINS + (helper.MANIFEST,)
    helper.ROOT_NAMES, helper.MTA_NAMES, helper.TOOLBOX_NAMES = (
        validator.ROOT_NAMES, validator.MTA_NAMES, validator.TOOLBOX_NAMES)
    target = helper.TARGET
    before = "(12509,'63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5')"
    need(target.count('4182249') == target.count(before) == 1, 'asset_template_identity')
    helper.TARGET = target.replace('4182249', str(ASSET_BYTES)).replace(before, repr(VALIDATOR[1:]))
    need(helper.TARGET.replace(str(ASSET_BYTES), '4182249').replace(
        repr(VALIDATOR[1:]), before) == target, 'asset_template_inverse')
    return helper


def graph_payload(graph, read, inputs):
    """Keep actual fixed75 order, independently pin FC9 without adding roles."""
    global FC_ROWS
    ordinary = graph.manifest_rows(read(graph.MANIFEST))
    private = graph.manifest_rows(read(graph.PRIVATE_MANIFEST), True)
    payload = ordinary + graph.HELPERS + private + (graph.WPA, graph.MONITOR)
    need(len(ordinary) == len(private) == 35 and len(payload) == 75 and
         len(set(row[0] for row in payload)) == 75 and
         sum(row[2] for row in payload) == PAYLOAD_BYTES <= 4194304, 'graph_roles')
    for name, path, size, sha in payload:
        read((path, size, sha))
    read(graph.RUNNER)
    for pin in graph.ORIGIN_SOURCE_PINS:
        read(pin)
    # Original manifest bytes remain private inputs to the mechanical check.
    read(graph.ORIGINAL_MANIFEST)
    read(graph.OLD_PRIVATE_MANIFEST)
    FC_ROWS = graph.FILECENTER_SOURCE_PINS
    need(type(FC_ROWS) is tuple and len(FC_ROWS) == 9 and
         sum(row[2] for row in FC_ROWS) == 113690 <= 131072, 'fc_source_budget')
    for name, path, size, sha in FC_ROWS:
        read((path, size, sha))
    need(graph.verify_inputs(inputs) == 7, 'graph_mechanical_verification')
    return payload


def ui_program(inputs, payload, runner, carrier):
    """Actual Receiver worker creates FC after startup and binds real guardian."""
    lines = ['import base64,hashlib,signal,sys,time,types,zlib',
             'started=time.monotonic();outer_until=started+800.0',
             'signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(20)',
             'def decode(data,size,sha):',
             ' d=zlib.decompressobj();raw=d.decompress(base64.b64decode(data,validate=True),size+1)',
             ' if len(raw)!=size or not d.eof or d.unused_data or d.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("source_pin")',
             ' return raw', 'sources={}']
    for name, pin in (('worker', WORKER), ('runner', runner), ('assets', VALIDATOR)):
        lines.append('sources[' + repr(name) + ']=decode((\n' + carrier.encoded(inputs[pin[0]]) +
                     '),' + repr(pin[1]) + ',' + repr(pin[2]) + ')')
    lines.append('artifacts=[]')
    for name, path, size, sha in payload:
        lines.append('artifacts.append((' + repr(name) + ',' + str(size) + ',' + repr(sha) +
                     ',decode((\n' + carrier.encoded(inputs[path]) + '),' + str(size) + ',' + repr(sha) + ')))')
    lines.append('fc=[]')
    for name, path, size, sha in FC_ROWS:
        lines.append('fc.append((' + repr(name) + ',decode((\n' + carrier.encoded(inputs[path]) +
                     '),' + str(size) + ',' + repr(sha) + ')))')
    wire = b'P011_FORMAL_RECEIVE_FILECENTER_UI_V1_SMOKE_ONLY\n'
    lines += ['wire=sys.stdin.buffer.read(' + str(len(wire)) + ')',
              'if wire!=' + repr(wire) + ':raise ValueError("wire_pin")',
              'remaining=outer_until-time.monotonic()',
              'if not 0<remaining<=800.0:raise ValueError("outer_deadline")',
              'signal.setitimer(signal.ITIMER_REAL,remaining)',
              'worker=types.ModuleType("fixed_formal_receive_filecenter_ui_v1_worker")',
              'worker.__file__="<fixed-formal-receive-filecenter-ui-v1-worker>"',
              'exec(compile(sources["worker"],worker.__file__,"exec"),worker.__dict__)',
              'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],smoke_only=True,filecenter_sources=tuple(fc))',
              'print("RESULT="+repr(component));print("MTA_REMOTE_OK")',
              'closed=(type(component)is dict and all(component.get(k)is True for k in ("candidate_exited","owner_close_verified","guardian_exited","worker_fds_closed","credentials_removed","filecenter_closed","filecenter_audio_settled")) and component.get("resource_pending")is False)',
              'if closed:signal.setitimer(signal.ITIMER_REAL,0.0)',
              'raise SystemExit(0 if component.get("complete")is True else 1)']
    raw = ('\n'.join(lines) + '\n').encode('ascii')
    # Reuse the already reviewed bounded private exception projection unchanged.
    anchor = b'print("RESULT="+repr(component));print("MTA_REMOTE_OK")\n'
    need(raw.count(anchor) == 1, 'diagnostic_anchor')
    return raw.replace(anchor, DIAGNOSTIC_RAW + anchor, 1), wire


def accepted(value, helper, ui):
    if ui:
        return (ORIGINAL_ACCEPTED(value, helper, True) is True and
                all(value[key] is True for key in FILECENTER_FIELDS))
    return (value['complete'] is True and value['reason'] == 'complete' and
            value['resource_pending'] is False and value['staging_pending'] is False and
            all(value[key] is True for key in helper.BOOL_FIELDS
                if key not in ('resource_pending', 'staging_pending')) and
            value['created_file_count'] in (0, 19) and value['created_directory_count'] in (0, 3, 4) and
            value['original_opened_fd_count'] == value['original_closed_fd_count'] > 0 and
            value['validator_opened_fd_count'] == value['validator_closed_fd_count'] == 27 and
            value['validator_files_verified'] == 19 and value['validator_readback_passes'] == 38)


def new_main(raw):
    original = ast.parse(raw, feature_version=(3, 5))
    rows = [row for row in original.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(rows) == 1, 'original_main_count')
    before = ast.Module(body=rows, type_ignores=[])
    tree = copy.deepcopy(before)
    changed = []
    replacements = (
        ('{}', '{ORIGIN[0]: ORIGIN_RAW, DIAGNOSTIC[0]: DIAGNOSTIC_SOURCE}'),
        ('ordinary + private_rows + graph.HELPERS + (graph.WPA, graph.MONITOR)', 'graph_payload(graph, read, inputs)'),
        ('4129184', 'PAYLOAD_BYTES'),
        ('4151735', 'ASSET_BYTES'),
        ('len(helper.PINS) == 9', 'len(helper.PINS) == 18'),
        ('len(helper.ASSET_PINS) == 10', 'len(helper.ASSET_PINS) == 19'),
        ("[dict(path=name, mode='0700') for name in ('', 'mta')]",
         "[dict(path=name, mode='0700') for name in ('', 'mta', 'toolbox')]"),
        ("stage['staged_file_count'] == 10", "stage['staged_file_count'] == 19"),
        ("stage['payload_file_count'] == 9", "stage['payload_file_count'] == 18"),
        ("stage['companion_required'] is False", "stage['companion_required'] is True"),
        ("stage['schema'] == 'p011-formal-receive-ui-v1-stage'",
         "stage['schema'] == 'p011-formal-receive-filecenter-ui-v1-stage'"),
        ("'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v1'",
         "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v1'"),
    )
    # Use shape-matched expressions only, not unbounded literal replacement.
    for source, target in replacements:
        matches = []
        for parent in ast.walk(tree):
            for field, child in ast.iter_fields(parent):
                children = [(child, at, item) for at, item in enumerate(child)] if type(child) is list else [(parent, field, child)]
                for container, slot, item in children:
                    if not isinstance(item, ast.AST) or shape(item) != shape(expression(source)):
                        continue
                    # Empty dict only means the initial inputs, not programs.
                    if source == '{}' and not (isinstance(parent, ast.Assign) and
                        any(isinstance(row, ast.Name) and row.id == 'inputs' for row in parent.targets)):
                        continue
                    matches.append((container, slot, item))
        expected = 2 if source == '4151735' else 1
        need(len(matches) == expected, 'main_delta_' + str(len(changed)))
        for parent, field, child in matches:
            value = expression(target)
            changed.append((parent, field, copy.deepcopy(child)))
            set_child(parent, field, value)
    # Report fields and the historical bundle label do not convey false scope.
    report = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
              len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'report']
    need(len(report) == 1 and isinstance(report[0].value, ast.Call), 'report_delta')
    report_keywords = []
    for row in ast.walk(tree):
        if isinstance(row, ast.keyword) and row.arg in ('second_credential_pair', 'companion_requested'):
            report_keywords.append((row, copy.deepcopy(row.value)))
            row.value = expression('args.ui_smoke')
        elif isinstance(row, ast.keyword) and row.arg == 'asset_files':
            need(shape(row.value) == shape(expression('10')), 'asset_report_count')
            report_keywords.append((row, copy.deepcopy(row.value)))
            row.value = expression('19')
    need(len(report_keywords) == 3, 'report_scope_count')
    labels = []
    for row in ast.walk(tree):
        if isinstance(row, ast.Constant) and row.value == 'formal-receive-ui-v1-':
            labels.append((row, row.value)); row.value = 'formal-receive-filecenter-ui-v1-'
    need(len(labels) == 1, 'result_label')
    readme = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
              len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme']
    need(len(readme) == 1, 'readme_delta')
    old_readme = copy.deepcopy(readme[0].value)
    readme[0].value = ast.Constant(value=(
        b'Default SOURCE. Explicit exclusive fixed19 asset stage is files only; actual UI smoke '
        b'is one true Receiver600+60 with launched+20 display and attached FC9 companion. '
        b'One original Receiver Owner, two actual distinct loopback credential pairs; not two MTA Owners. '
        b'Original39 facts and seven FileCenter facts required; no auto RF/audio/file/phone. '
        b'Native stage60+60/alarm180, fixed75 roles/4MiB, FC9/131072 and bootstrap2MiB unchanged. '
        b'Partial/unknown assets, historical outputs and carrier retained. Raw logs/input bytes/private '
        b'bounded exception detail stay private; public ZIP is metadata/README only. '
        b'SOURCE is not P011 visual/touch, receive/send, phone, network or restoration acceptance.\n'))
    # Restore every edited object in this same tree; the inverse must be exact.
    # This is a structural source audit, not runtime/Owner admission.
    final = copy.deepcopy(tree)
    for parent, field, original in reversed(changed):
        set_child(parent, field, original)
    for row, original in report_keywords: row.value = original
    for row, original in labels: row.value = original
    readme[0].value = old_readme
    need(shape(tree) == shape(before), 'main_inverse_delta')
    return ast.fix_missing_locations(final)


ORIGIN_RAW = fixed(ORIGIN)
DIAGNOSTIC_MODULE, DIAGNOSTIC_SOURCE = definitions(DIAGNOSTIC, 'fixed_fc_ui_private_diagnostic_source')
DIAGNOSTIC_RAW = DIAGNOSTIC_MODULE.DIAGNOSTIC
ORIGINAL_ACCEPTED = None


def main():
    global ORIGINAL_ACCEPTED
    need(all(pin[1] > 0 and len(pin[2]) == 64 for pin in (WORKER, VALIDATOR, DEFINITIONS, STAGE_MANIFEST)) and
         len(SESSION) == 24 and 0 < ASSET_BYTES < 4194304 and 0 < PAYLOAD_BYTES <= 4194304,
         'new_composition_unsealed')
    old, raw = definitions(ORIGIN, 'new_receive_filecenter_ui_carrier_definitions')
    ORIGINAL_ACCEPTED = old.accepted
    old.SELF, old.CMDS = SELF, CMDS
    for name in ('SESSION', 'BUNDLE', 'REMOTE', 'WORKER', 'VALIDATOR', 'DEFINITIONS',
                 'STAGE_MANIFEST', 'NATIVE', 'ASSET_BYTES', 'PAYLOAD_BYTES', 'ORIGIN',
                 'ORIGIN_RAW', 'DIAGNOSTIC', 'DIAGNOSTIC_SOURCE'):
        old.__dict__[name] = globals()[name]
    old.UI_BOOLS = old.UI_BOOLS + FILECENTER_FIELDS
    old.UI_FIELDS = frozenset(old.UI_BOOLS + old.UI_COUNTS + old.UI_REASONS)
    old.asset_helper, old.graph_payload, old.ui_program, old.accepted = (
        asset_helper, graph_payload, ui_program, accepted)
    exec(compile(new_main(raw), str(BASE / SELF), 'exec'), old.__dict__)
    return old.main()


if __name__ == '__main__':
    raise SystemExit(main())
