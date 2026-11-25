"""No-observer Receiver/FileCenter UI comparison with bounded private diagnosis.

SOURCE by default. The actual UI trial uses the same frozen core, FC9, QRC,
600+60 profile, launched+20 display and original cleanup gates. Only the
exclusive control directory differs. Do not run a target screenshot waiter
during Startup. Historical v1 results and inputs remain immutable.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v2_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V2_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V2.cmd')
ORIGINAL = ('host/device_formal_receive_filecenter_ui_v1_check.py', 16312,
            '2388ba10e035ca42f250af557cfa040cbe2a16a4aa0d19e58027e89d9bba58c0')
OLD_WORKER = ('candidate/formal-receive-filecenter-ui-v1/runtime/ui_session.py', 91414,
              '06eae9cb05ffc2c9fa04bfe3f5101e6d8b8bb8b0fcf9712bb3d7983f55048b9e')
# ROOT seals the agent-created inverse-identical worker before execution.
WORKER = ('candidate/formal-receive-filecenter-ui-v2/runtime/ui_session.py', 91414,
          '9f529fc41b3dd847174547b9e2aab4ee0153e66c84986f35a965a16e715c0272')
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v2'"
OLD_WORKER_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v1'"
NEW_WORKER_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v2'"

# No exception text, args, paths, resource values, raw records or arbitrary
# locals are inspected. The one permitted local is the original `error` in
# the exact retained private BaselineCollector.collect traceback frame. Its
# code AND globals must match the actually bound private module. This runs
# after the original worker's cleanup; it performs no target IO or callbacks.
INNER_DIAGNOSTIC = b'''try:
 inner_retained=worker._RETAINED
 inner_component=inner_retained.get("component") if type(inner_retained)is dict else None
 inner_owner=getattr(inner_component,"owner",None)
 inner_scope=getattr(inner_component,"startup_scope",None)
 inner_modules=getattr(inner_scope,"private_modules",None)
 inner_collection=getattr(inner_component,"startup_collection",None)
 inner_ticket=getattr(inner_scope,"collector_ticket",None)
 inner_bound=(inner_owner is not None and inner_scope is getattr(inner_owner,"_startup_scope_original",None) and inner_scope is getattr(inner_owner,"startup_scope",None) and type(inner_modules)is dict and type(inner_ticket)is dict and inner_collection is not None and inner_collection is inner_ticket.get("returned") and getattr(inner_collection,"scope",None)is inner_scope and getattr(inner_collection,"modules",None)is inner_modules)
 inner_baseline=inner_modules.get("mta_client_baseline") if inner_bound else None
 inner_module=getattr(inner_owner,"_startup_module_original",None) if inner_bound else None
 if type(inner_baseline)is types.ModuleType and type(inner_module)is types.ModuleType and type(inner_collection)is inner_module.StartupCollection:
  inner_code=inner_baseline.BaselineCollector.collect.__code__
  inner_roots=(getattr(inner_owner,"startup_failure",None),getattr(inner_collection,"failure",None))
  inner_selected=[];inner_seen=set()
  for inner_outer in inner_roots:
   if not isinstance(inner_outer,BaseException):continue
   inner_tb=inner_outer.__traceback__;inner_walked=0
   while inner_tb is not None and inner_walked<64:
    inner_frame=inner_tb.tb_frame
    if inner_frame.f_code is inner_code and inner_frame.f_globals is inner_baseline.__dict__:
     inner_error=inner_frame.f_locals.get("error")
     if isinstance(inner_error,BaseException) and id(inner_error)not in inner_seen:
      inner_selected.append(inner_error);inner_seen.add(id(inner_error))
    inner_walked+=1;inner_tb=inner_tb.tb_next
   if len(inner_selected)>=2:break
  for inner_error in inner_selected[:2]:
   inner_kind=type(inner_error).__name__
   if type(inner_kind)is not str or not 0<len(inner_kind)<=96 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in inner_kind):inner_kind="bounded_type"
   inner_errno=getattr(inner_error,"errno",None)
   if type(inner_errno)is not int or not -2147483648<=inner_errno<=2147483647:inner_errno=None
   inner_error_code=getattr(inner_error,"code",None)
   if type(inner_error_code)is not str or inner_error_code not in inner_baseline._CODES|inner_module._CODES:inner_error_code=None
   inner_tb=inner_error.__traceback__;inner_frames=[];inner_walked=0
   while inner_tb is not None and inner_walked<64:
    inner_frame=inner_tb.tb_frame;inner_alias=None
    if inner_frame.f_globals is inner_baseline.__dict__:inner_alias="baseline"
    elif inner_frame.f_globals is inner_module.__dict__:inner_alias="startup"
    inner_name=inner_frame.f_code.co_name if inner_alias is not None else None
    if type(inner_name)is not str or not 0<len(inner_name)<=96 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in inner_name):inner_name=None
    inner_line=inner_tb.tb_lineno if inner_alias is not None else None
    if type(inner_line)is not int or not 0<=inner_line<=2147483647:inner_line=None
    inner_frames.append((inner_alias,inner_name,inner_line));inner_frames=inner_frames[-8:]
    inner_walked+=1;inner_tb=inner_tb.tb_next
   sys.stderr.write("PRIVATE_UI_BASELINE_INNER="+repr((inner_kind,inner_error_code,inner_errno,inner_walked,inner_tb is not None,tuple(inner_frames)))+"\\n")
  inner_collector=getattr(inner_collection,"collector",None)
  if inner_collector is not None and inner_collector is getattr(inner_collection,"_collector_original",None) and isinstance(inner_collector,inner_baseline.BaselineCollector):
   inner_counts=[]
   for inner_name in ("reader_rows","status_rows","constructor_rows"):
    inner_rows=getattr(inner_collection,inner_name,None)
    inner_counts.append(len(inner_rows) if type(inner_rows)is list and len(inner_rows)<=8320 else None)
   for inner_name in ("_tickets","_observations","_rounds"):
    inner_rows=getattr(inner_collector,inner_name,None)
    inner_counts.append(len(inner_rows) if type(inner_rows)is list and len(inner_rows)<=8320 else None)
   inner_flags=tuple(value if type(value)is bool else None for value in (getattr(inner_collection,"io_started",None),getattr(inner_collection,"ended",None),getattr(inner_collection,"success",None),getattr(inner_collector,"_attempted",None),getattr(inner_collector,"_ended",None),getattr(inner_collector,"_pending",None)))
   sys.stderr.write("PRIVATE_UI_BASELINE_PARTIAL="+repr((tuple(inner_counts),inner_flags))+"\\n")
except BaseException:
 pass
'''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'comparison_source_pin')
    return raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def expression(raw):
    return ast.parse(raw, mode='eval').body


def comparison_main(original, original_raw, old_worker_raw):
    """Inverse-audit only the isolated log root, label and retained PC inputs."""
    def adapted(raw):
        tree = original(raw)
        old_tree = copy.deepcopy(tree)
        controls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                    len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                    row.targets[0].id == 'control']
        seeds = [row for row in tree.body[0].body if isinstance(row, ast.Assign) and
                 len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                 row.targets[0].id == 'inputs']
        labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and
                  row.value == 'formal-receive-filecenter-ui-v1-']
        need(len(controls) == len(seeds) == len(labels) == 1 and
             shape(controls[0].value) == shape(expression(OLD_CONTROL)) and
             isinstance(seeds[0].value, ast.Dict), 'comparison_original_shape')
        controls[0].value = expression(NEW_CONTROL)
        labels[0].value = 'formal-receive-filecenter-ui-v2-'
        seed_old = copy.deepcopy(seeds[0].value)
        for path, value in ((ORIGINAL[0], original_raw), (OLD_WORKER[0], old_worker_raw)):
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        final = copy.deepcopy(tree)
        controls[0].value = expression(OLD_CONTROL)
        labels[0].value = 'formal-receive-filecenter-ui-v1-'
        seeds[0].value = seed_old
        need(shape(tree) == shape(old_tree), 'comparison_inverse_main')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    original_raw, old_worker_raw, worker_raw = fixed(ORIGINAL), fixed(OLD_WORKER), fixed(WORKER)
    need(old_worker_raw.count(OLD_WORKER_CONTROL) == worker_raw.count(NEW_WORKER_CONTROL) == 1 and
         worker_raw.replace(NEW_WORKER_CONTROL, OLD_WORKER_CONTROL, 1) == old_worker_raw,
         'comparison_inverse_worker')
    ast.parse(worker_raw, feature_version=(3, 5))
    ast.parse(INNER_DIAGNOSTIC, feature_version=(3, 5))
    original = types.ModuleType('fixed_fc_ui_v2_original_definitions')
    original.__file__ = str(BASE / ORIGINAL[0])
    exec(compile(original_raw, original.__file__, 'exec'), original.__dict__)
    original.SELF, original.CMDS, original.WORKER = SELF, CMDS, WORKER
    original.new_main = comparison_main(original.new_main, original_raw, old_worker_raw)
    original.DIAGNOSTIC_RAW += INNER_DIAGNOSTIC
    # Definitions-only reuse. This invokes only the newly compiled main, not
    # the archived v1 main body. No target screenshot observer is dispatched.
    return original.main()


if __name__ == '__main__':
    raise SystemExit(main())
