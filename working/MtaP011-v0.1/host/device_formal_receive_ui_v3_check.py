"""Thin private Receive UI failure diagnostic; frozen v2/v1 behavior retained.

Default SOURCE. The explicit TEST CMD selects the same genuine Receive UI smoke.
Only the generated bootstrap gains a bounded, private stderr projection after
the original worker returns. No Exception args/locals, tickets, profile or raw
baseline is inspected. No diagnostic is emitted when no retained Exception is
present. The original public component, acceptance and every cleanup gate stay
unchanged. Actual pinned v1/v2 source bytes enter the inherited private inputs.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_ui_v3_check.py'
CMD = 'TEST_MTA_FORMAL_RECEIVE_UI_V3.cmd'
V2 = ('host/device_formal_receive_ui_v2_check.py', 7058,
      '495b502aa3e2de64a8d66e77f3f5bacf3a9f1bc9ba274d4d814ebe3f906b9dca')
V1 = ('host/device_formal_receive_ui_v1_check.py', 24136,
      'f72c802ab8fbec8cc1e0b228ed8c779dd69752b9fa279ad1b966558c4d095857')
OLD_WORKER = ('candidate/formal-receive-ui-v1/runtime/ui_session.py', 57490,
              'b3ca0e8ca285ece326f089f06a749599daa579debea2d0fc046b404da153fee6')
WORKER = ('candidate/formal-receive-ui-v3-diag/runtime/ui_session.py', 57495,
          '75948d9865f0a140a9aed45eb283ce394eafa2f023f6530da6887a4ee0087b6e')
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v3-diag'"
OLD_WORKER_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v1'"
NEW_WORKER_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v3-diag'"
ANCHOR = b'print("RESULT="+repr(component));print("MTA_REMOTE_OK")\n'

# These fields are actual retainers in the frozen Receive Owner/collection and
# worker/FixedSession sources, not guessed names or recursive object traversal.
# Bound the retained Exception list and original traceback objects independently.
DIAGNOSTIC = b'''try:
 diag_retained=worker._RETAINED
 diag_component=diag_retained.get("component") if type(diag_retained)is dict else None
 diag_owner=getattr(diag_component,"owner",None)
 diag_collection=getattr(diag_owner,"startup_result",None)
 diag_roots=(getattr(diag_collection,"failure",None),getattr(diag_collection,"close_failure",None),getattr(diag_owner,"startup_failure",None),getattr(diag_owner,"failure",None))
 diag_worker_failures=diag_retained.get("failures") if type(diag_retained)is dict else None
 diag_component_failures=getattr(diag_component,"failures",None)
 diag_sources=(diag_roots,diag_worker_failures,diag_component_failures)
 diag_selected=[];diag_seen=set()
 for diag_source in diag_sources:
  if type(diag_source)not in (tuple,list):continue
  for diag_error in diag_source[:64]:
   if isinstance(diag_error,BaseException) and id(diag_error)not in diag_seen:
    diag_seen.add(id(diag_error));diag_selected.append(diag_error)
    if len(diag_selected)==8:break
  if len(diag_selected)==8:break
 if diag_selected:
  sys.stderr.write("PRIVATE_UI_FAILURE_BEGIN\\n")
  for diag_at,diag_error in enumerate(diag_selected):
   diag_kind=type(diag_error).__name__
   if type(diag_kind)is not str or not 0<len(diag_kind)<=96 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in diag_kind):diag_kind="bounded_type"
   diag_code=getattr(diag_error,"code",None)
   if type(diag_code)is not str or not 0<len(diag_code)<=96 or diag_code[0]not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_" or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in diag_code):diag_code=None
   diag_errno=getattr(diag_error,"errno",None)
   if type(diag_errno)is not int or not -2147483648<=diag_errno<=2147483647:diag_errno=None
   diag_tb=diag_error.__traceback__;diag_frames=[];diag_walked=0
   while diag_tb is not None and diag_walked<64:
    diag_frame_code=diag_tb.tb_frame.f_code
    diag_filename,diag_name,diag_line=diag_frame_code.co_filename,diag_frame_code.co_name,diag_tb.tb_lineno
    if type(diag_filename)is not str or len(diag_filename)>512:diag_filename=None
    if type(diag_name)is not str or len(diag_name)>96:diag_name=None
    if type(diag_line)is not int or not 0<=diag_line<=2147483647:diag_line=None
    diag_frames.append((diag_filename,diag_name,diag_line));diag_frames=diag_frames[-8:]
    diag_walked+=1;diag_tb=diag_tb.tb_next
   sys.stderr.write("PRIVATE_UI_FAILURE="+repr((diag_at,diag_kind,diag_code,diag_errno,diag_walked,diag_tb is not None,tuple(diag_frames)))+"\\n")
  sys.stderr.write("PRIVATE_UI_FAILURE_END\\n")
except BaseException:
 pass
'''


def need(value, code):
    if value is not True: raise ValueError(code)


def shape(node): return ast.dump(node, include_attributes=False)


def expression(source): return ast.parse(source, mode='eval').body


def fixed_definitions(pin, name):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'diagnostic_original_pin')
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    need(module.BASE == BASE, 'diagnostic_original_base')
    return module, raw


def v3_main(tree):
    """Retain v2 main; bind private inputs/revision3 and the new exclusive log root."""
    new = copy.deepcopy(tree)
    need(len(new.body) == 1 and isinstance(new.body[0], ast.FunctionDef) and
         new.body[0].name == 'main', 'diagnostic_main_count')
    seeds = []; revisions = []; controls = []
    for row in new.body[0].body:
        if not isinstance(row, ast.Assign) or len(row.targets) != 1 or not isinstance(row.targets[0], ast.Name):
            continue
        if row.targets[0].id == 'inputs': seeds.append(row)
        if row.targets[0].id == 'report' and isinstance(row.value, ast.Call):
            revisions.extend(item for item in row.value.keywords if item.arg == 'driver_revision')
    for row in ast.walk(new):
        if (isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control'):
            controls.append(row)
    need(len(seeds) == len(revisions) == len(controls) == 1 and
         shape(seeds[0].value) == shape(expression('{V2_ORIGINAL[0]: V2_ORIGINAL_RAW}')) and
         shape(revisions[0].value) == shape(expression('2')) and
         shape(controls[0].value) == shape(expression(OLD_CONTROL)), 'diagnostic_main_original')
    seeds[0].value = expression('{V2_ORIGINAL[0]: V2_ORIGINAL_RAW, V3_ORIGINAL[0]: V3_ORIGINAL_RAW, V3_OLD_WORKER[0]: V3_OLD_WORKER_RAW}')
    revisions[0].value = expression('3')
    controls[0].value = expression(NEW_CONTROL)
    audit = copy.deepcopy(new)
    for row in audit.body[0].body:
        if not isinstance(row, ast.Assign) or len(row.targets) != 1 or not isinstance(row.targets[0], ast.Name):
            continue
        if row.targets[0].id == 'inputs': row.value = expression('{V2_ORIGINAL[0]: V2_ORIGINAL_RAW}')
        if row.targets[0].id == 'report' and isinstance(row.value, ast.Call):
            for item in row.value.keywords:
                if item.arg == 'driver_revision': item.value = expression('2')
    for row in ast.walk(audit):
        if (isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control'):
            row.value = expression(OLD_CONTROL)
    need(shape(audit) == shape(tree), 'diagnostic_inverse_main')
    return ast.fix_missing_locations(new)


def diagnostic_program(original):
    """Keep the returned wire and every original program byte outside one anchor."""
    ast.parse(DIAGNOSTIC, feature_version=(3, 5))
    need(DIAGNOSTIC.count(b'PRIVATE_UI_FAILURE_BEGIN') == 1 and
         DIAGNOSTIC.count(b'PRIVATE_UI_FAILURE_END') == 1 and ANCHOR not in DIAGNOSTIC,
         'diagnostic_source_shape')

    def ui_program(inputs, payload, runner, carrier):
        program, wire = original(inputs, payload, runner, carrier)
        need(type(program) is bytes and type(wire) is bytes and program.count(ANCHOR) == 1,
             'diagnostic_program_anchor')
        patched = program.replace(ANCHOR, DIAGNOSTIC + ANCHOR, 1)
        need(patched.count(DIAGNOSTIC) == 1 and patched.replace(DIAGNOSTIC, b'', 1) == program,
             'diagnostic_inverse_program')
        return patched, wire
    return ui_program


def main():
    v2, v2_raw = fixed_definitions(V2, 'fixed_receive_ui_v3_v2_definitions')
    need(v2.ORIGINAL == V1, 'diagnostic_original_chain')
    v1, v1_raw = fixed_definitions(V1, 'fixed_receive_ui_v3_v1_definitions')
    need(v1.WORKER == OLD_WORKER, 'diagnostic_worker_original')
    old_worker_raw = (BASE / OLD_WORKER[0]).read_bytes()
    new_worker_raw = (BASE / WORKER[0]).read_bytes()
    need((len(old_worker_raw), hashlib.sha256(old_worker_raw).hexdigest()) == OLD_WORKER[1:] and
         (len(new_worker_raw), hashlib.sha256(new_worker_raw).hexdigest()) == WORKER[1:] and
         old_worker_raw.count(OLD_WORKER_CONTROL) == new_worker_raw.count(NEW_WORKER_CONTROL) == 1 and
         new_worker_raw.replace(NEW_WORKER_CONTROL, OLD_WORKER_CONTROL, 1) == old_worker_raw,
         'diagnostic_inverse_worker')
    ast.parse(new_worker_raw, feature_version=(3, 5))
    v1.SELF, v1.CMDS = SELF, (CMD,)
    v1.WORKER = WORKER
    v1.V2_ORIGINAL, v1.V2_ORIGINAL_RAW = V1, v1_raw
    v1.V3_ORIGINAL, v1.V3_ORIGINAL_RAW = V2, v2_raw
    v1.V3_OLD_WORKER, v1.V3_OLD_WORKER_RAW = OLD_WORKER, old_worker_raw
    v1.v2_payload_order = v2.v2_payload_order
    v1.ui_program = diagnostic_program(v1.ui_program)
    exec(compile(v3_main(v2.patched_main(v1_raw)), str(BASE / SELF), 'exec'), v1.__dict__)
    return v1.main()


if __name__ == '__main__': raise SystemExit(main())
