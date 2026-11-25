"""Independent mutex sender GUI carrier; default SOURCE, explicit smoke20.

Only fixed runtime/FC9/CONTROL bindings are propagated into the measured status
carrier. Its real 17-field Worker, GUI19/BUNDLE/SESSION, guardian, original
600+60 activity/cleanup, carrier800/HOST810, raw streams, retained resources,
stock/finally and strict completeness gates remain. No QML/asset rebuild,
Stage, CONTROL request, business HTTP/media, scan, send or phone is automatic.
The sole new SOURCE callback checks the actual fourteen mutex artifacts, not
the historical status27 closure. SOURCE evidence is not runtime acceptance.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_fc_mutex_ui_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FC_MUTEX_UI_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_FC_MUTEX_UI_V1_SOURCE_CHECK.cmd'
MOTHER = ('host/device_formal_send_status_ui_v1_check.py', 10897,
          '2cffbaa0f86bcf4f5e73b2c1fbc7dcf16c91f731da311d66db57f1e7f5bb024a')
PREPARE_PINS = (
    MOTHER,
    ('host/device_formal_send_preflight_ui_v1_check.py', 19048,
     'fcbf17242702204af54476798dffcc402f748b32a8f05a50933df695a3e9120e'),
    ('host/device_formal_send_repair_ui_v1_check.py', 13163,
     '3efc100b3a91fa5b6cdf9dc3f51a9c545d3fbc1a885d0c3ab288823997dc390c'),
    ('host/device_formal_send_filecenter_ui_v7_check.py', 28635,
     'b888055f21b21eb60d003e8dd00fde62646ef1dd2628d568146b987689ed2449'),
    ('host/device_formal_send_status_ui_assets_v1_check.py', 15921,
     '7f1d9a506c980f64daaea8f6bb327301c5f4626d4592b45de8a1d59abc002ee8'),
)
SOURCE_BOUNDARY = ('host/device_formal_send_fc_mutex_stage_v1_check.py', 16003,
                   'dd14baba8f04ed4efe33cb9057acad7383aee05b5572ce2f31accd701154a2c0')
SOURCE_BASELINES = PREPARE_PINS + (SOURCE_BOUNDARY,)
RUNTIME = 'candidate/formal-send-fc-mutex-v1/runtime/'
SESSION = '6d4fb1fd4af949cbb3515870'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-mutex1-v1'
CONTROL_SUFFIX = '-formal-send-fc-mutex-v1'
FC_MANIFEST = ('candidate/formal-send-fc-mutex-v1/assets/filecenter-source-manifest.json', 2477,
               '611ca4aa72fb01e7f4393a0e789344ee0590846c5dc955380aba141d689c59e3')
WORKER = (RUNTIME + 'ui_session.py', 46411,
          '84a68c021ac5b4f0e01fbbe8bb41dcb226113c11f380725a317ae9bcab034fc8')
GUARDIAN = (RUNTIME + 'ui_guardian.py', 43988,
            '93a3d16cd580d841f11324ed5a31be4b676f0377ffb44d6552bc0d5ed32b43b5')
VALIDATOR = (RUNTIME + 'ui_assets.py', 12526,
             '430308223593d5d783c1ec1d29a90dcbe82606b33690fc263572b8353d9fd4e8')
OUTER = (RUNTIME + 'formal_send_session.py', 24060,
         '364b85bd8b95aa79373319a0671e14f2e20ca4c98cf78f0e918628d9a88dcc6b')
PREPARE_NAMES = frozenset(('need', 'digest', 'tree', 'assignment', 'span',
    'pure_definitions', 'source_boundary', 'derive_host', 'prepare'))
UI_BOOLS = ('complete', 'ui_ready', 'credentials_removed', 'original_ui_exited', 'candidate_exited',
    'owner_closed', 'guardian_exited', 'stock_restored', 'worker_fds_closed', 'resource_pending',
    'automatic_rf_action', 'receive_worker_started', 'filecenter_parent_deadline_verified',
    'filecenter_parent_deadline_wired', 'smoke_requested')
UI_FIELDS = frozenset(UI_BOOLS + ('automatic_stop_seconds', 'reason'))


def need(value):
    if value is not True:
        raise ValueError('mutex_ui_source_contract')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(inputs, row):
    raw = inputs[row[0]] if row[0] in inputs else (BASE / row[0]).read_bytes()
    inputs[row[0]] = raw
    need(type(raw) is bytes and (len(raw), digest(raw)) == row[1:])
    return raw


def pure(inputs, row, names, label):
    raw = fixed(inputs, row)
    chosen = [node for node in ast.parse(raw).body if
              isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
              isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in chosen if isinstance(node, ast.FunctionDef)} == set(names) and
         'main' not in names)
    module = types.ModuleType(label)
    module.__file__ = str(BASE / row[0])
    exec(compile(ast.Module(body=chosen, type_ignores=[]), '<' + label + '>', 'exec'), module.__dict__)
    need('main' not in module.__dict__)
    return module


def assignment(raw, name):
    rows = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1)
    return rows[0]


def span(raw, node):
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def derive(origin):
    """Finite bindings plus one report DATA field; no carrier branch edits."""
    raw, ledger = origin, []

    def change(before, after, count=1):
        nonlocal raw
        need(type(before) is bytes and type(after) is bytes and before != after and raw.count(before) == count)
        raw = raw.replace(before, after)
        ledger.append((before, after, count))

    replacements = dict(SELF=SELF, CMD=CMD, RUNTIME=RUNTIME, WORKER=WORKER,
                        GUARDIAN=GUARDIAN, VALIDATOR=VALIDATOR, OUTER=OUTER,
                        SOURCE_BASELINES=SOURCE_BASELINES)
    for name, value in replacements.items():
        change(span(raw, assignment(raw, name)), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    change(b"path='candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json'",
           ('path=' + repr(FC_MANIFEST[0])).encode('ascii'))
    change(b"(2466,'14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')",
           ('(' + str(FC_MANIFEST[1]) + ',' + repr(FC_MANIFEST[2]) + ')').encode('ascii'))
    change(b'99972', b'101682', 2)
    change(b"+SESSION+'-formal-send-status-package-v3'", ("+SESSION+" + repr(CONTROL_SUFFIX)).encode('ascii'))
    change(b"for path in (SELF,CMD,CONTRACT,'HOST_MTA_FORMAL_SEND_STATUS_UI_V1_SOURCE_CHECK.cmd'):",
           ('for path in (SELF,CMD,CONTRACT,' + repr(SOURCE_CMD) + '):').encode('ascii'))
    change(b'fixed_sender_status_ui_v1_', b'fixed_sender_fc_mutex_ui_v1_', 5)
    change(b'fixed-sender-status-ui-v1-', b'fixed-sender-fc-mutex-ui-v1-', 1)
    change(b'formal_send_status_ui_v1_fixed_carrier_entry', b'formal_send_fc_mutex_ui_v1_fixed_carrier_entry')
    change(b'fixed-formal-send-status-ui-v1-bootstrap', b'fixed-formal-send-fc-mutex-ui-v1-bootstrap')
    change(b'fixed-status-ui-v1-carrier', b'fixed-fc-mutex-ui-v1-carrier')
    change(b"('formal-send-status-ui-v1-'+mode+", b"('formal-send-fc-mutex-ui-v1-'+mode+")
    change(b'original_window_seconds=600,original_cleanup_seconds=60,ui_smoke_seconds=20,',
           b'original_window_seconds=600,original_cleanup_seconds=60,ui_smoke_seconds=20,package_provenance=_MUTEX_UI_SOURCE_FACTS,')
    inverse = raw
    for before, after, count in reversed(ledger):
        need(inverse.count(after) == count)
        inverse = inverse.replace(after, before)
    need(inverse == origin and ast.dump(ast.parse(inverse), include_attributes=True) ==
         ast.dump(ast.parse(origin), include_attributes=True))

    def neutral(node, remove_data=False):
        value = ast.parse(span(raw if remove_data else origin, node))
        if remove_data:
            keywords = [item for item in ast.walk(value) if isinstance(item, ast.keyword) and
                        item.arg == 'package_provenance']
            if keywords:
                need(len(keywords) == 1 and isinstance(keywords[0].value, ast.Name) and
                     keywords[0].value.id == '_MUTEX_UI_SOURCE_FACTS')
                calls = [item for item in ast.walk(value) if isinstance(item, ast.Call) and
                         any(key is keywords[0] for key in item.keywords)]
                need(len(calls) == 1 and isinstance(calls[0].func, ast.Name) and calls[0].func.id == 'dict')
                calls[0].keywords.remove(keywords[0])
        class Literals(ast.NodeTransformer):
            def visit_Constant(self, item):
                return ast.copy_location(ast.Constant(value=None), item)
        return ast.dump(Literals().visit(value), include_attributes=False)

    old_nodes, new_nodes = ast.parse(origin).body, ast.parse(raw).body
    need(len(old_nodes) == len(new_nodes))
    changed_assignments, changed_methods = set(), set()
    allowed = {'ui_program', 'carrier_body', 'carrier_command', 'main'}
    for old, new in zip(old_nodes, new_nodes):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            if isinstance(old, (ast.FunctionDef, ast.ClassDef)):
                need(span(origin, old) == span(raw, new))
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            need(len(old.targets) == len(new.targets) == 1 and isinstance(old.targets[0], ast.Name) and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]) and old.targets[0].id in replacements)
            changed_assignments.add(old.targets[0].id)
        else:
            need(isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef) and
                 old.name == new.name and old.name in allowed and neutral(old) == neutral(new, True))
            changed_methods.add(old.name)
    need(changed_assignments == set(replacements) and changed_methods == allowed)
    return raw, dict(complete_byte_inverse=True, complete_positioned_ast_inverse=True,
        other_carrier_methods_byte_exact=True, changed_methods_only_literals_and_report_data=True,
        changed_assignments=sorted(changed_assignments), changed_methods=sorted(changed_methods),
        finite_substitutions=len(ledger), report_data_fields_added=1,
        derived_host_bytes=len(raw), derived_host_sha256=digest(raw), old_main_called=False)


def prepare():
    inputs = {}
    for row in PREPARE_PINS:
        fixed(inputs, row)
    previous = pure(inputs, MOTHER, PREPARE_NAMES, '_mutex_ui_measured_status_pure')
    old, origin = previous.prepare()
    need(old.UI_FIELDS == UI_FIELDS and old.UI_BOOLS == UI_BOOLS and
         old.SESSION == SESSION and old.BUNDLE == BUNDLE and old.REMOTE == REMOTE and
         old.OUTER == previous.OUTER and old.WORKER == previous.WORKER and
         old.GUARDIAN == previous.GUARDIAN and old.VALIDATOR == previous.VALIDATOR)
    raw, proof = derive(origin)
    module = types.ModuleType('_formal_send_fc_mutex_ui_v1_fixed_carrier')
    module.__file__ = str(BASE / SELF)
    exec(compile(raw, '<mutex-ui-v1-fixed-carrier>', 'exec'), module.__dict__)
    need(module.SELF == SELF and module.CMD == CMD and module.RUNTIME == RUNTIME and
         module.SESSION == SESSION and module.BUNDLE == BUNDLE and module.REMOTE == REMOTE and
         module.WORKER == WORKER and module.GUARDIAN == GUARDIAN and module.VALIDATOR == VALIDATOR and
         module.OUTER == OUTER and module.SOURCE_BASELINES == SOURCE_BASELINES and
         module.UI_FIELDS == UI_FIELDS and module.UI_BOOLS == UI_BOOLS)
    facts = dict(scope='SOURCE_PROVENANCE_NOT_RUNTIME', boundary_complete=False,
        carrier_source_proof=proof, fixed_status_pure_sources=[list(row) for row in PREPARE_PINS],
        ordinary_root=ROOT, new_control_suffix=CONTROL_SUFFIX,
        gui19_rebuilt=False, gui19_staged=False, fc9_staged=False, ui_started=False, rf_requested=False,
        filecenter_parent_deadline_verified=False, filecenter_media_mutex_device_verified=False,
        blocking_file_io_preemption_verified=False, old_tests_run=0, old_main_called=False,
        original_window_seconds=600, original_cleanup_seconds=60, original_smoke_seconds=20,
        original_carrier_seconds=800, original_host_timeout_seconds=810)
    module._MUTEX_UI_SOURCE_FACTS = facts

    def source_boundary(snapshot, helper, validator):
        for key, value in inputs.items():
            need(key not in snapshot or snapshot[key] == value)
            snapshot[key] = value
        source = pure(snapshot, SOURCE_BOUNDARY, {'need', 'fixed', 'pure', 'package_boundary'},
                      '_mutex_ui_actual_fourteen_source_only')
        need(all(name not in source.__dict__ for name in ('main', 'load', 'stage_methods', 'derive')))
        package, closure = source.package_boundary(snapshot)
        need(source.ROOT == ROOT and source.FC_MANIFEST == FC_MANIFEST and
             closure['actual_package_outputs'] == 14 and closure['actual_published_outputs_byte_exact'] is True and
             closure['full_package_byte_inverse'] is True and closure['fc9_sources'] == 9 and
             closure['fc9_bytes'] == 101682 and closure['fc9_cap'] == 131072 and
             closure['ordinary_batch_files'] == 37 and closure['ordinary_batch_bytes'] == 1368142 and
             closure['gui_unchanged_files'] == 19 and closure['gui_unchanged_bytes'] == 4185296)
        for row in (WORKER, GUARDIAN, VALIDATOR, OUTER, FC_MANIFEST):
            fixed(snapshot, row)
        need(validator.SESSION == SESSION and validator.REMOTE == REMOTE and
             len(validator.PINS) + 1 == 19 and
             sum(row[1] for row in validator.PINS) + validator.MANIFEST_PIN[0] == 4185296 and
             package.literal(snapshot[OUTER[0]], 'ROOT') == '/tmp/' + ROOT.rsplit('/', 1)[1] and
             package.literal(snapshot[OUTER[0]], 'PHYSICAL_ROOT') == ROOT)
        facts.update(boundary_complete=True, package_closure=closure,
            fc9_sources=9, fc9_bytes=101682, fc9_cap=131072,
            gui_unchanged_files=19, gui_unchanged_bytes=4185296)
        return True

    # Replace only the passive SOURCE callback. No historical status27 check,
    # parent/Worker method, carrier IO or final completeness predicate runs here.
    module._STATUS_UI_SOURCE_BOUNDARY = source_boundary
    return module, raw


def main():
    need(sys.argv[1:] in ([], ['--check-device']))
    module, raw = prepare()
    # Only the independently bound carrier's unchanged main is dispatched.
    # Its --check-device branch really uses original smoke20 and 800/810.
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())
