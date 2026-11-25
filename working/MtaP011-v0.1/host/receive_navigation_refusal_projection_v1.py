"""SOURCE helper for finite cached navigation-refusal DATA after run_fixed.

The explicit HOST may append TARGET_FRAGMENT after the original Worker return.
It reads only one exact original navigation failure traceback and its retained
cached dict/bools/diagnostic tuple. It calls no business method, clock, device,
resource IO or callback. The sole output is a bounded private stderr record;
the 51 public UI fields, FAIL result, admission and close path are unchanged.
Trial copy, cancelled observer and idle observation occurred in that order;
they are separate observations, not one atomic or physical radio receipt.
"""
import ast
import hashlib
import json


TARGET_FRAGMENT = b'''def _receive_navigation_refusal_projection_v1(worker):
 import sys,types
 stage="worker_binding"
 try:
  if type(worker)is not types.ModuleType:raise ValueError()
  namespace=worker.__dict__
  run=namespace.get("run_fixed")
  need=namespace.get("need")
  error_type=namespace.get("UiSessionError")
  retained=namespace.get("_RETAINED")
  if type(run)is not types.FunctionType or run.__globals__ is not namespace or run.__code__.co_firstlineno!=1246:raise ValueError()
  if type(need)is not types.FunctionType or need.__globals__ is not namespace or need.__code__.co_firstlineno!=112 or type(error_type)is not type or type(retained)is not dict:raise ValueError()
  if error_type.__module__!=namespace.get("__name__") or type(error_type.__init__)is not types.FunctionType or error_type.__init__.__globals__ is not namespace:raise ValueError()
  component=retained.get("component")
  failures=retained.get("failures")
  observer=retained.get("navigation_observer")
  stage="component_binding"
  if type(observer)is not tuple or len(observer)!=3 or type(failures)is not list or len(failures)>64:raise ValueError()
  cls,method,code=observer
  if type(cls)is not type or type(component)is not cls or type(method)is not types.FunctionType or type(code)is not types.CodeType:raise ValueError()
  runner_namespace=method.__globals__
  if type(runner_namespace)is not dict or runner_namespace.get("FixedSession")is not cls or cls.__dict__.get("original_receive_ui_cancelled_empty")is not method:raise ValueError()
  if method.__code__ is not code or code.co_firstlineno!=816 or cls.__module__!=runner_namespace.get("__name__"):raise ValueError()
  stage="navigation_traceback"
  matches=[]
  for error in failures:
   if type(error)is not error_type:continue
   error_fields=error.__dict__
   if type(error_fields)is not dict:raise ValueError()
   reason=error_fields.get("code")
   if type(reason)is not str or reason!="navigation_receive_activity":continue
   tb=error.__traceback__
   walked=0
   local=None
   need_bound=False
   while tb is not None and walked<64:
    frame=tb.tb_frame
    if frame.f_globals is namespace and frame.f_code is run.__code__:
     if local is not None or tb.tb_lineno!=1557:raise ValueError()
     local=frame.f_locals
     original_runner=local.get("runner")
     if local.get("component")is not component or type(original_runner)is not types.ModuleType or original_runner.__dict__ is not runner_namespace:raise ValueError()
     if local.get("navigation_test")is not True or local.get("smoke_only")is not False:raise ValueError()
    if frame.f_globals is namespace and frame.f_code is need.__code__:
     fields=frame.f_locals
     if need_bound or fields.get("condition")is not False or fields.get("code")!="navigation_receive_activity":raise ValueError()
     need_bound=True
    walked+=1
    tb=tb.tb_next
   if tb is not None or local is None or not need_bound:raise ValueError()
   matches.append(local)
  if not matches:
   sys.stderr.write("PRIVATE_RECEIVE_NAVIGATION_REFUSAL_NOT_APPLICABLE=no_original_navigation_failure\\n")
   sys.stderr.flush()
   return
  if len(matches)!=1:raise ValueError()
  local=matches[0]
  trial=local.get("trial_observed")
  idle=local.get("navigation_idle")
  cancelled=local.get("cancelled_empty")
  diagnostic=local.get("navigation_cancelled_diagnostic")
  stage="finite_cached_data"
  if type(trial)is not dict or type(idle)is not bool or type(cancelled)is not bool:raise ValueError()
  names=("requested","available","claimed","session_attached","revoked","expired")
  values=tuple(trial.get(name) for name in names)
  count=trial.get("claim_count")
  reason=trial.get("reason")
  reasons=("not_requested","ready","claimed","revoked","expired","owner_context","source_changed","startup_unknown","probe_unknown","radio_unknown","radio_unavailable","radio_busy","network_spec_unknown","barrier_unknown","state_not_idle","claim_changed","already_claimed","session_unknown","owner_stopped","owner_closed","cancelled","state_closing","operation_failed","session_failed","not_started","clear","wrong_worker","deadline","unsupported_platform","unsafe_anchor","anchor_changed","alias_changed","pending_exists","pending_symlink","client_root_missing","client_history","inventory_unknown","descriptor_unknown","io_error","close_unknown","already_attempted")
  if any(type(value)is not bool for value in values) or type(count)is not int or count not in (0,1):raise ValueError()
  if type(reason)is not str or reason not in reasons:raise ValueError()
  stage="original_observer_data"
  groups=("owner","http","types","bound_trial","trial_cancel","trial_empty","epochs","inventory","resources","collections","probes","events")
  kinds=("false","attribute","key","type","value","runtime","bounded_exception")
  if type(diagnostic)is not tuple or len(diagnostic)!=3:raise ValueError()
  failed,passed,kind=diagnostic
  if type(failed)is not str or type(passed)is not tuple or type(kind)is not str or len(passed)>len(groups):raise ValueError()
  if any(type(name)is not str for name in passed) or passed!=groups[:len(passed)]:raise ValueError()
  if kind=="true":
   if failed!="none" or passed!=groups or cancelled is not True:raise ValueError()
  elif kind in kinds:
   if cancelled is not False:raise ValueError()
   if len(passed)==len(groups):
    if kind=="false" or failed!="lock_exit":raise ValueError()
   elif failed!=groups[len(passed)]:raise ValueError()
  else:raise ValueError()
  # Cached fields are DATA. Never repeat the original short-circuited guard.
  row=("receive-navigation-refusal-projection-v1",(idle,cancelled),tuple(zip(names,values)),count,reason,diagnostic)
  sys.stderr.write("PRIVATE_RECEIVE_NAVIGATION_REFUSAL="+repr(row)+"\\n")
  sys.stderr.flush()
 except BaseException:
  try:
   sys.stderr.write("PRIVATE_RECEIVE_NAVIGATION_REFUSAL_UNKNOWN="+repr(stage)+"\\n")
   sys.stderr.flush()
  except BaseException:pass
_receive_navigation_refusal_projection_v1(worker)
'''

DIAGNOSTIC_RAW = TARGET_FRAGMENT


def source_facts():
    """Parse only; never execute the target or import historical modules."""
    ast.parse(TARGET_FRAGMENT.decode('ascii'),
              filename='<receive-navigation-refusal-projection-v1>', feature_version=(3, 5))
    if not 0 < len(TARGET_FRAGMENT) <= 8192:
        raise ValueError('projection_budget')
    return dict(mode='source-only', target_executed=False, device=False,
                target_bytes=len(TARGET_FRAGMENT),
                target_sha256=hashlib.sha256(TARGET_FRAGMENT).hexdigest(),
                traceback_limit=64, failure_limit=64, frame_matches=1,
                cached_data=True, admission=False, new_clock=False, resource_io=False)


def main():
    print(json.dumps(source_facts(), sort_keys=True))


if __name__ == '__main__':
    main()
