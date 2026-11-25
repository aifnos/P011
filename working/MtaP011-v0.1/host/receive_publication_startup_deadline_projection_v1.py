"""PC SOURCE helper: a finite after-run deadline projection, not admission.

The literal below runs only when an explicit HOST inserts it after the original
worker.run_fixed return.  Default execution parses the literal; it never runs
the target, opens a device, calls a clock, or changes the frozen core/cleanup.
Only the exact check_active traceback frame's `self` and `value` are inspected.
No exception text/args, paths, credentials, arbitrary locals, or resource IO.
"""

import ast
import hashlib
import json


TARGET_FRAGMENT = b'''def _receive_startup_deadline_projection_v1(worker):
 import sys,types
 stage="worker_binding"
 try:
  if type(worker)is not types.ModuleType:raise ValueError()
  namespace=worker.__dict__
  run=namespace.get("run_fixed")
  retained=namespace.get("_RETAINED")
  if type(run)is not types.FunctionType or run.__globals__ is not namespace or type(retained)is not dict:raise ValueError()
  component=retained.get("component")
  failures=retained.get("failures")
  if component is None or type(failures)is not list or len(failures)>64:raise ValueError()
  stage="owner_binding"
  owner=component.owner
  owner_module=component.owner_module
  if type(owner_module)is not types.ModuleType:raise ValueError()
  owner_namespace=owner_module.__dict__
  owner_type=owner_namespace.get("FixedStateServiceOwner")
  if type(owner_type)is not type or type(owner)is not owner_type or owner._startup_owner_type_original is not owner_type or owner._startup_namespace_original is not owner_namespace:raise ValueError()
  if type(owner_type._startup_readonly)is not types.FunctionType or owner_type._startup_readonly.__globals__ is not owner_namespace:raise ValueError()
  error=owner.startup_failure
  if error is None:return
  if not any(error is original for original in failures):raise ValueError()
  stage="factory_binding"
  loader=owner.loader
  if loader is not component.loader or type(loader.modules)is not dict or type(loader.module_originals)is not list or len(loader.module_originals)>64:raise ValueError()
  module=loader.modules.get("mta_client_receive_factory")
  if type(module)is not types.ModuleType or sys.modules.get("mta_client_receive_factory")is not module:raise ValueError()
  module_namespace=module.__dict__
  originals=[row for row in loader.module_originals if type(row)is tuple and len(row)==3 and row[0]=="mta_client_receive_factory"]
  if len(originals)!=1 or originals[0][1]is not module or originals[0][2]is not module_namespace:raise ValueError()
  factory_type=module_namespace.get("FixedReceiveDeploymentFactory")
  scope_type=module_namespace.get("_StartupReadScope")
  error_type=module_namespace.get("ReceivePublicationError")
  factory=owner.factory
  if type(factory_type)is not type or type(scope_type)is not type or type(error_type)is not type or type(factory)is not factory_type or type(error)is not error_type:raise ValueError()
  if loader.factory_returned is not factory or owner._startup_factory_original is not factory:raise ValueError()
  startup=factory_type.startup_readonly
  check=scope_type.check_active
  if type(startup)is not types.FunctionType or type(check)is not types.FunctionType or startup.__globals__ is not module_namespace or check.__globals__ is not module_namespace:raise ValueError()
  if factory_type.__module__!=module.__name__ or scope_type.__module__!=module.__name__ or check.__code__.co_firstlineno!=504:raise ValueError()
  stage="scope_binding"
  scope=owner.startup_scope
  if type(scope)is not scope_type or scope is not owner._startup_scope_original or scope is not factory._startup_scope or scope.failure is not error:raise ValueError()
  if scope.owner is not owner or scope.factory is not factory or scope.loader is not loader or scope.owner_type is not owner_type or scope.owner_namespace is not owner_namespace:raise ValueError()
  until=scope.original_until
  if scope.until is not until or owner.original_until is not until or owner.until is not until or loader._original_until is not until:raise ValueError()
  stage="failure_traceback"
  tb=error.__traceback__
  walked=0
  matches=[]
  importing_call=False
  while tb is not None and walked<64:
   frame=tb.tb_frame
   if frame.f_globals is module_namespace and frame.f_code is startup.__code__ and tb.tb_lineno==1336:importing_call=True
   if frame.f_globals is module_namespace and frame.f_code is check.__code__ and tb.tb_lineno==514:
    local=frame.f_locals
    if local.get("self")is not scope:raise ValueError()
    matches.append(local.get("value"))
   walked+=1
   tb=tb.tb_next
  if tb is not None or len(matches)!=1:raise ValueError()
  value=matches[0]
  prepare=scope.prepare_until
  original_prepare=scope.original_prepare_until
  stage="finite_numbers"
  for number in (value,until):
   if type(number)not in (int,float) or not 0<=number<1e12:raise ValueError()
  for number in (prepare,original_prepare):
   if number is not None and (type(number)not in (int,float) or not 0<=number<1e12):raise ValueError()
  # The after-close `scope.phase` is intentionally never read as failure phase.
  # Only the exact original startup_readonly:1177 call site proves importing.
  failure_phase="importing" if importing_call else "unknown"
  parent_expired=value>=until
  prepare_identity_changed=prepare is not None and prepare is not original_prepare
  prepare_above_parent=prepare is not None and prepare>until
  phase_prepare_expired=(prepare is not None and value>=prepare) if importing_call else None
  parent_remaining=float(until)-float(value)
  prepare_remaining=None if prepare is None else float(prepare)-float(value)
  original_prepare_remaining=None if original_prepare is None else float(original_prepare)-float(value)
  for difference in (parent_remaining,prepare_remaining,original_prepare_remaining):
   if difference is not None and not -1e12<difference<1e12:raise ValueError()
  row=("receive-startup-deadline-projection-v1",failure_phase,(parent_expired,prepare_identity_changed,prepare_above_parent,phase_prepare_expired),(parent_remaining,prepare_remaining,original_prepare_remaining))
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_DEADLINE="+repr(row)+"\\n")
  if not importing_call:sys.stderr.write("PRIVATE_RECEIVE_STARTUP_DEADLINE_UNKNOWN="+repr(("failure_phase","unknown_callsite"))+"\\n")
  sys.stderr.flush()
 except BaseException as projection_error:
  kind=type(projection_error).__name__
  if type(kind)is not str or not 0<len(kind)<=96 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in kind):kind="bounded_type"
  try:
   sys.stderr.write("PRIVATE_RECEIVE_STARTUP_DEADLINE_UNKNOWN="+repr((stage,kind))+"\\n")
   sys.stderr.flush()
  except BaseException:
   pass
_receive_startup_deadline_projection_v1(worker)
'''

# Existing thin HOSTs use this name for their after-run literal insertion seam.
DIAGNOSTIC_RAW = TARGET_FRAGMENT


def source_facts():
    """Parse only: no target execution, old imports, tests, graph, or device IO."""
    ast.parse(TARGET_FRAGMENT.decode('ascii'), filename='<receive-startup-deadline-projection-v1>',
              feature_version=(3, 5))
    if len(TARGET_FRAGMENT) >= 8192:
        raise ValueError('projection_budget')
    return dict(mode='source-only', target_executed=False, device=False,
                target_bytes=len(TARGET_FRAGMENT),
                target_sha256=hashlib.sha256(TARGET_FRAGMENT).hexdigest(),
                traceback_limit=64, frame_matches=1, admission=False)


def main():
    print(json.dumps(source_facts(), sort_keys=True))


if __name__ == '__main__':
    main()
