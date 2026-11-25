"""SOURCE-only helper for five retained, original Startup clock boundaries.

An explicit carrier may append the fixed literal after the unchanged Worker
returns. This projection is diagnostic DATA only. It calls no clock, IO,
Owner/Scope business method, device or admission check. Missing/stale markers
remain unknown; the last segment must not be called pure importer wall-time.
"""
import ast
import hashlib
import json


TARGET_FRAGMENT = r'''def _receive_startup_boundary_projection_v1(worker):
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
  startup_owner=owner_type._startup_readonly
  if type(startup_owner)is not types.FunctionType or startup_owner.__globals__ is not owner_namespace:raise ValueError()
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
  factory=owner.factory
  if type(factory_type)is not type or type(scope_type)is not type or type(factory)is not factory_type:raise ValueError()
  if loader.factory_returned is not factory or owner._startup_factory_original is not factory:raise ValueError()
  startup=factory_type.startup_readonly
  check=scope_type.check_active
  if type(startup)is not types.FunctionType or type(check)is not types.FunctionType or startup.__globals__ is not module_namespace or check.__globals__ is not module_namespace:raise ValueError()
  if factory_type.__module__!=module.__name__ or scope_type.__module__!=module.__name__ or check.__code__.co_firstlineno!=504:raise ValueError()
  stage="scope_binding"
  scope=owner.startup_scope
  if type(scope)is not scope_type or scope is not owner._startup_scope_original or scope is not factory._startup_scope:raise ValueError()
  if scope.owner is not owner or scope.factory is not factory or scope.loader is not loader or scope.owner_type is not owner_type or scope.owner_namespace is not owner_namespace:raise ValueError()
  fields=scope.__dict__
  if type(fields)is not dict:raise ValueError()
  names=("startup_boundary_init","startup_boundary_private_sources","startup_boundary_wpa","startup_boundary_profile","startup_boundary_postimport")
  values=tuple(fields.get(name) for name in names)
  stage="finite_markers"
  previous=None
  missing=False
  for value in values:
   if value is None:missing=True;continue
   if missing or type(value)not in (int,float) or not 0<=value<1e12:raise ValueError()
   if previous is not None and value<previous:raise ValueError()
   previous=value
  if values[0]is None:raise ValueError()
  stage="original_postimport_sample"
  sampled=None
  error=owner.startup_failure
  if fields.get("success")is True:
   if fields.get("read_ended")is not True:raise ValueError()
   if values[-1]is not None:sampled=True
  else:
   if error is None or scope.failure is not error or not any(error is original for original in failures):raise ValueError()
   tb=error.__traceback__
   walked=0
   importing_call=False
   samples=[]
   while tb is not None and walked<64:
    frame=tb.tb_frame
    if frame.f_globals is module_namespace and frame.f_code is startup.__code__ and tb.tb_lineno==1336:importing_call=True
    if frame.f_globals is module_namespace and frame.f_code is check.__code__ and tb.tb_lineno==514:
     local=frame.f_locals
     if local.get("self")is not scope:raise ValueError()
     samples.append(local.get("value"))
    walked+=1
    tb=tb.tb_next
   if tb is not None:raise ValueError()
   if importing_call and len(samples)==1 and type(samples[0])in (int,float) and values[-1]is not None and values[-1]==samples[0]:sampled=True
  # Recent original clock samples, not function-return times. The final
  # difference includes profile tail, row assembly, hashes, imports and checks.
  deltas=tuple(None if values[index]is None or values[index-1]is None else float(values[index])-float(values[index-1]) for index in range(1,5))
  elapsed=None if values[-1]is None else float(values[-1])-float(values[0])
  row=("receive-startup-boundary-projection-v1",tuple(value is not None for value in values),deltas,elapsed,sampled)
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_BOUNDARIES="+repr(row)+"\n")
  sys.stderr.flush()
 except BaseException as projection_error:
  kind=type(projection_error).__name__
  if type(kind)is not str or not 0<len(kind)<=96 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in kind):kind="bounded_type"
  try:
   sys.stderr.write("PRIVATE_RECEIVE_STARTUP_BOUNDARIES_UNKNOWN="+repr((stage,kind))+"\n")
   sys.stderr.flush()
  except BaseException:
   pass
_receive_startup_boundary_projection_v1(worker)
'''.encode('ascii')

DIAGNOSTIC_RAW = TARGET_FRAGMENT


def source_facts():
    """Parse the fixed literal only; do not execute it or historical sources."""
    ast.parse(TARGET_FRAGMENT.decode('ascii'),
              filename='<receive-startup-boundary-projection-v1>', feature_version=(3, 5))
    if not 0 < len(TARGET_FRAGMENT) <= 8192:
        raise ValueError('projection_budget')
    return dict(mode='source-only', target_executed=False, device=False,
                target_bytes=len(TARGET_FRAGMENT),
                target_sha256=hashlib.sha256(TARGET_FRAGMENT).hexdigest(),
                admission=False, new_clock=False, io=False)


def main():
    print(json.dumps(source_facts(), sort_keys=True))


if __name__ == '__main__':
    main()
