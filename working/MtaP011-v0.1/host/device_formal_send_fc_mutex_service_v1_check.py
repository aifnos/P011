"""One independent mutex FileCenter service diagnostic; default PC SOURCE.

Derive only the frozen, actually passed v3 service carrier's package constants,
FC9 byte counts and result identities. The same real Parent/Boot/Owner creates
the nine in-memory sources and closes immediately. Original60+60/alarm180/
HOST210, stock/carrier/IO/finally/strictclose and fixed-user-directory policy
remain. No business HTTP, media, credentials, UI, CONTROL, RF, phone, old suite,
old main, Stage, package writer, GUI rebuild or deadline extension is added.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_fc_mutex_service_v1_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FC_MUTEX_SERVICE_V1_CHECK.cmd'
TEST_CMD = 'TEST_MTA_FORMAL_SEND_FC_MUTEX_SERVICE_V1.cmd'
MOTHER = ('host/device_formal_send_filecenter_service_v3_check.py', 27635,
          'd46345e6361cd06398cfd73786dc2cbaf746ade6ef3a80ee21c099ea365acbc5')
SOURCE_BOUNDARY = ('host/device_formal_send_fc_mutex_stage_v1_check.py', 16003,
                   'dd14baba8f04ed4efe33cb9057acad7383aee05b5572ce2f31accd701154a2c0')
ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-mutex1-v1'
CATALOG = ('candidate/formal-send-fc-mutex-v1/assets/filecenter-source-manifest.json', 2477,
           '611ca4aa72fb01e7f4393a0e789344ee0590846c5dc955380aba141d689c59e3')
OUTER = ('candidate/formal-send-fc-mutex-v1/runtime/formal_send_session.py', 24060,
         '364b85bd8b95aa79373319a0671e14f2e20ca4c98cf78f0e918628d9a88dcc6b')
BOOT = ('candidate/formal-send-fc-mutex-v1/runtime/mta_client_receive_boot.py', 19583,
        'b8d33d2437b44637190d110f8ed8e874f45b3ce9b4850da848b82d05eab64ec4')
OWNER = ('candidate/formal-send-fc-mutex-v1/runtime/mta_client_service_owner.py', 103959,
         '769b19c90c8c1160e553f0632a9f90ff19fbd8425e7e2d5d0d92662ef3aa0ac1')


def need(value):
    if value is not True:
        raise ValueError('source_shape')


def fixed(inputs, row):
    raw = inputs[row[0]] if row[0] in inputs else (BASE / row[0]).read_bytes()
    inputs[row[0]] = raw
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:])
    return raw


def derive(raw):
    """Finite data edits only; full byte/positioned AST inverse, no old main."""
    changes = (
        ("SELF = 'host/device_formal_send_filecenter_service_v3_check.py'", 'SELF = ' + repr(SELF), 1),
        ("CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_SERVICE_V3.cmd'", 'CMD = ' + repr(CMD), 1),
        ("CATALOG = ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json', 2466,\n"
         "           '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')",
         "CATALOG = ('candidate/formal-send-fc-mutex-v1/assets/filecenter-source-manifest.json', 2477,\n"
         "           '611ca4aa72fb01e7f4393a0e789344ee0590846c5dc955380aba141d689c59e3')", 1),
        ("OUTER = ('candidate/formal-send-filecenter-deploy-v3/runtime/formal_send_session.py', 24059,\n"
         "         '010372da6947869cc4bce3b6ce5471fe36c389bef4ad057981e5f6246a6f519a')",
         "OUTER = ('candidate/formal-send-fc-mutex-v1/runtime/formal_send_session.py', 24060,\n"
         "         '364b85bd8b95aa79373319a0671e14f2e20ca4c98cf78f0e918628d9a88dcc6b')", 1),
        ("BOOT = ('candidate/formal-send-filecenter-deploy-v3/runtime/mta_client_receive_boot.py', 19583,\n"
         "        'b9390c26bf10e16463e83ecce6bc188c3b3d9838e95f119901376f049f2c66a1')",
         "BOOT = ('candidate/formal-send-fc-mutex-v1/runtime/mta_client_receive_boot.py', 19583,\n"
         "        'b8d33d2437b44637190d110f8ed8e874f45b3ce9b4850da848b82d05eab64ec4')", 1),
        ("OWNER = ('candidate/formal-send-filecenter-deploy-v3/runtime/mta_client_service_owner.py', 82772,\n"
         "         '5ebd7843c41df1322e9a408fc659b412ff85421ac049f3f1bf1e019edd5439a5')",
         "OWNER = ('candidate/formal-send-fc-mutex-v1/runtime/mta_client_service_owner.py', 103959,\n"
         "         '769b19c90c8c1160e553f0632a9f90ff19fbd8425e7e2d5d0d92662ef3aa0ac1')", 1),
        ('99972', '101682', 3),
        ('124031', '125742', 1),
        ('formal-send-filecenter-v3-service-diagnostic', 'formal-send-fc-mutex-v1-service-diagnostic', 3),
        ('formal-send-filecenter-service-v3-', 'formal-send-fc-mutex-service-v1-', 1),
        ('Fixed v3 real service and FileCenter diagnostic. Default is PC-only source construction.',
         'Fixed mutex real service and FileCenter diagnostic. Default is PC-only source construction.', 1),
        ('retained_carrier=True)',
         'retained_carrier=True, package_provenance=_MUTEX_SERVICE_SOURCE_FACTS)', 1),
    )
    original, ledger = raw, []
    for before, after, count in changes:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count and before.count(b'\n') == after.count(b'\n'))
        positions = [index for index in range(len(raw)) if raw.startswith(before, index)]
        for offset in reversed(positions):
            need(raw[offset:offset + len(before)] == before)
            raw = raw[:offset] + after + raw[offset + len(before):]
            ledger.append((offset, before, after))
    inverse = raw
    for offset, before, after in reversed(ledger):
        need(inverse[offset:offset + len(after)] == after)
        inverse = inverse[:offset] + before + inverse[offset + len(after):]
    need(inverse == original and ast.dump(ast.parse(inverse), include_attributes=True) ==
         ast.dump(ast.parse(original), include_attributes=True))
    old, new = ast.parse(original).body, ast.parse(raw).body
    need(len(old) == len(new))
    allowed = {'make_program', 'service_result', 'service_complete', 'main'}
    changed = set()
    for first, second in zip(old, new):
        if isinstance(first, (ast.FunctionDef, ast.ClassDef)):
            need(type(first) is type(second) and first.name == second.name and
                 (first.lineno, first.end_lineno) == (second.lineno, second.end_lineno))
            a = ast.get_source_segment(original.decode('ascii'), first)
            b = ast.get_source_segment(raw.decode('ascii'), second)
            if a != b:
                need(first.name in allowed)
                changed.add(first.name)
    need(changed == allowed)
    body = [node.value for node in new if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
            node.targets[0].id == 'SERVICE_BODY']
    need(len(body) == 1)
    ast.parse(ast.literal_eval(body[0]), feature_version=(3, 5))
    return raw, dict(complete_byte_inverse=True, complete_positioned_ast_inverse=True,
        unchanged_other_carrier_helpers_byte_exact=True, finite_data_edits=len(ledger),
        changed_host_methods=sorted(changed), added_report_data_only=True,
        original_service_calls_guards_close_and_caps_unchanged=True,
        old_main_executed=False, derived_host_bytes=len(raw),
        derived_host_sha256=hashlib.sha256(raw).hexdigest())


def boundary(inputs):
    """Reuse only four reviewed pure SOURCE helpers, never Stage/load/main."""
    raw = fixed(inputs, SOURCE_BOUNDARY)
    names = {'need', 'fixed', 'pure', 'package_boundary'}
    chosen = [node for node in ast.parse(raw).body if
              isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
              isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in chosen if isinstance(node, ast.FunctionDef)} == names)
    module = types.ModuleType('_mutex_service_package_source_only')
    module.__file__ = str(BASE / SOURCE_BOUNDARY[0])
    exec(compile(ast.Module(body=chosen, type_ignores=[]), module.__file__, 'exec'), module.__dict__)
    need(all(name not in module.__dict__ for name in ('load', 'main', 'stage_methods', 'derive')))
    package, facts = module.package_boundary(inputs)
    need(module.ROOT == ROOT and module.FC_MANIFEST == CATALOG and
         facts['actual_published_outputs_byte_exact'] is True and
         facts['ordinary_batch_files'] == 37 and facts['ordinary_batch_bytes'] == 1368142 and
         facts['fc9_sources'] == 9 and facts['fc9_bytes'] == 101682 and facts['fc9_cap'] == 131072)
    need(package.literal(fixed(inputs, OUTER), 'ROOT') == '/tmp/' + ROOT.rsplit('/', 1)[1] and
         package.literal(inputs[OUTER[0]], 'PHYSICAL_ROOT') == ROOT)
    return facts


def load():
    inputs = {}
    raw, proof = derive(fixed(inputs, MOTHER))
    module = types.ModuleType('_formal_send_fc_mutex_service_v1_fixed_carrier')
    module.__file__ = str(BASE / SELF)
    exec(compile(raw, '<mutex-service-v1-fixed-carrier>', 'exec'), module.__dict__)
    need(module.SELF == SELF and module.CMD == CMD and module.CATALOG == CATALOG and
         module.OUTER == OUTER and module.BOOT == BOOT and module.OWNER == OWNER)
    facts = dict(scope='SOURCE_PROVENANCE_NOT_RUNTIME', boundary_complete=False,
        carrier_source_proof=proof, original_service_mother=list(MOTHER),
        ordinary_root=ROOT, filecenter_parent_deadline_verified=False,
        filecenter_media_mutex_device_verified=False, blocking_file_io_preemption_verified=False,
        gui19_staged=False, fc9_staged=False, ui_started=False, rf_requested=False,
        old_tests_run=0, old_main_executed=False, original_parent_seconds=60,
        original_cleanup_seconds=60, original_alarm_seconds=180, original_host_seconds=210)
    module._MUTEX_SERVICE_SOURCE_FACTS = facts
    inherited = module.make_program

    def make_program(snapshot):
        for key, value in inputs.items():
            need(key not in snapshot or snapshot[key] == value)
            snapshot[key] = value
        for path in (SELF, CMD, TEST_CMD):
            value = (BASE / path).read_bytes()
            need(path not in snapshot or snapshot[path] == value)
            snapshot[path] = value
        closure = boundary(snapshot)
        facts.update(boundary_complete=True, package_closure=closure,
                     fc9_sources=9, fc9_bytes=101682, fc9_cap=131072,
                     in_memory_sources=10, in_memory_source_bytes=125742)
        program = inherited(snapshot)
        facts['program_prepared'] = True
        return program

    module.make_program = make_program
    return module


def main():
    # Original parser: default PC-only, explicit --check-device only. Its local
    # mode label and every original execution/strict closing branch stay intact.
    return load().main()


if __name__ == '__main__':
    raise SystemExit(main())
