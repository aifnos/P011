"""One passive function appended after the unchanged Worker has returned.

Only retained, exact builtin DATA is counted. raw bytes lengths are logical
retained lengths, not verified-complete reads, syscall counts, CPU time or
physical memory. Missing raw remains missing; incoming/parts are not inspected.
No clock, filesystem, guard, callback, path/PID output or admission is added.
"""

TARGET_FRAGMENT = r'''def _receive_startup_workload_projection_v1(worker):
 import sys,types
 stage="worker"
 try:
  if type(worker)is not types.ModuleType:raise ValueError()
  namespace=worker.__dict__
  run=namespace.get("run_fixed");retained=namespace.get("_RETAINED")
  if type(run)is not types.FunctionType or run.__globals__ is not namespace or run.__code__.co_firstlineno!=1246 or type(retained)is not dict:raise ValueError()
  observer=retained.get("navigation_observer");component=retained.get("component")
  if type(observer)is not tuple or len(observer)!=3 or type(observer[0])is not type or type(component)is not observer[0]:raise ValueError()
  fields=component.__dict__
  if type(fields)is not dict:raise ValueError()
  owner=fields.get("owner");owner_module=fields.get("owner_module")
  stage="owner"
  if type(owner_module)is not types.ModuleType:raise ValueError()
  owner_namespace=owner_module.__dict__;owner_type=owner_namespace.get("FixedStateServiceOwner")
  if type(owner_type)is not type or type(owner)is not owner_type:raise ValueError()
  owner_fields=owner.__dict__
  if owner_fields.get("_startup_owner_type_original")is not owner_type or owner_fields.get("_startup_namespace_original")is not owner_namespace:raise ValueError()
  loader=owner_fields.get("loader");factory=owner_fields.get("factory")
  if loader is not fields.get("loader"):raise ValueError()
  loader_fields=loader.__dict__
  modules=loader_fields.get("modules");originals=loader_fields.get("module_originals")
  if type(modules)is not dict or type(originals)is not list or len(originals)>64:raise ValueError()
  module=modules.get("mta_client_receive_factory")
  if type(module)is not types.ModuleType or sys.modules.get("mta_client_receive_factory")is not module:raise ValueError()
  module_namespace=module.__dict__
  bound=[row for row in originals if type(row)is tuple and len(row)==3 and row[0]=="mta_client_receive_factory"]
  if len(bound)!=1 or bound[0][1]is not module or bound[0][2]is not module_namespace:raise ValueError()
  factory_type=module_namespace.get("FixedReceiveDeploymentFactory");scope_type=module_namespace.get("_StartupReadScope");files_type=module_namespace.get("_Files")
  if type(factory_type)is not type or type(scope_type)is not type or type(files_type)is not type or type(factory)is not factory_type:raise ValueError()
  if factory is not loader_fields.get("factory_returned") or factory is not owner_fields.get("_startup_factory_original"):raise ValueError()
  stage="scope"
  scope=owner_fields.get("startup_scope")
  if type(scope)is not scope_type or scope is not owner_fields.get("_startup_scope_original") or scope is not factory.__dict__.get("_startup_scope"):raise ValueError()
  scope_fields=scope.__dict__
  if scope_fields.get("owner")is not owner or scope_fields.get("factory")is not factory or scope_fields.get("loader")is not loader:raise ValueError()
  files=scope_fields.get("files")
  if type(files)is not files_type or files is not scope_fields.get("_files_original"):raise ValueError()
  files_fields=files.__dict__;rows=files_fields.get("rows")
  if files_fields.get("attempt")is not scope or type(rows)is not list or len(rows)>512:raise ValueError()
  stage="retained_rows"
  root=module_namespace.get("ASSET_PHYSICAL_ROOT");pins=module_namespace.get("SOURCE_PINS")
  if root!="/var/volatile/tmp/p011-mta-rx-durable-v1" or type(pins)is not tuple or len(pins)!=35:raise ValueError()
  private=[]
  for pin in pins:
   if type(pin)is not tuple or len(pin)!=3 or type(pin[0])is not str or not 1<=len(pin[0])<=96:raise ValueError()
   private.append(root+"/runtime35/"+pin[0]+".py")
  if len(set(private))!=35:raise ValueError()
  groups=[[0,0,0,0]for unused in range(4)]
  for entry in rows:
   if type(entry)is not dict or entry.get("owner")is not files:raise ValueError()
   path=entry.get("path");raw=entry.get("raw")
   if type(path)is not str or not 1<=len(path)<=4096 or raw is not None and type(raw)is not bytes:raise ValueError()
   index=3
   if path in private:index=0
   elif path==root+"/native/mta-wpa-supplicant":index=1
   else:
    parts=path.split("/")
    if len(parts)==4 and parts[:2]==["","proc"] and parts[3]=="comm":
     value=parts[2]
     if not 1<=len(value)<=10 or value[0]=="0" or any(c not in "0123456789"for c in value) or not 0<int(value)<=2147483647:raise ValueError()
     index=2
   group=groups[index];group[0]+=1
   if raw is None:group[3]+=1
   else:
    size=len(raw)
    if size>67108864:raise ValueError()
    group[1]+=1;group[2]+=size
  stage="retained_discovery"
  discovery=scope_fields.get("proc_discovery_rows")
  counts=None
  if discovery is not None:
   if type(discovery)is not list or len(discovery)>4096:raise ValueError()
   counts=[len(discovery),0,0,0,0,0]
   for entry in discovery:
    if type(entry)is not dict:raise ValueError()
    skip=entry.get("skip")
    if skip is None:counts[1]+=1
    elif type(skip)is str and skip=="nonroot_directory":counts[2]+=1
    elif type(skip)is str and skip=="disappeared_before_comm":counts[3]+=1
    else:raise ValueError()
    counts[4]+=entry.get("stat_result")is not None
    counts[5]+=entry.get("error")is not None
  names=("private35","private_wpa","proc_comm","profile_other")
  row=("receive-startup-workload-v1",tuple((name,tuple(group))for name,group in zip(names,groups)),None if counts is None else tuple(counts))
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_WORKLOAD="+repr(row)+"\n")
  sys.stderr.flush()
 except BaseException:
  try:
   sys.stderr.write("PRIVATE_RECEIVE_STARTUP_WORKLOAD_UNKNOWN="+repr(stage)+"\n")
   sys.stderr.flush()
  except BaseException:pass
_receive_startup_workload_projection_v1(worker)
'''.encode('ascii')
