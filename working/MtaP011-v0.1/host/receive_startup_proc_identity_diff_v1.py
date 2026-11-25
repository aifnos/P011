"""SOURCE-only, private after-return Proc identity difference projection.

Append TARGET_FRAGMENT immediately after the unchanged original PROC fragment.
Its function returns only bounded builtin DATA from the last ended generation
and the original error traceback; only the outer fragment writes private stderr.
No reader, guard, clock, stable_key, directory, close, parser or callback is
invoked. This is neither a business fix nor admission or restoration evidence.
The frozen original PROC/runtime and all original results remain unchanged.
"""
import ast
import hashlib
import json


TARGET_FRAGMENT = b'''def _receive_startup_proc_identity_diff_v1(worker,context):
 stage="prior_proc_projection"
 try:
  if type(context)is not dict or context.get("st")!="finite_projection" or context.get("inner_bound")is not True:raise ValueError()
  if type(worker)is not types.ModuleType:raise ValueError()
  namespace=worker.__dict__;run=namespace.get("run_fixed");retained=namespace.get("_RETAINED")
  if type(run)is not types.FunctionType or run.__globals__ is not namespace or run.__code__.co_firstlineno!=1246 or type(retained)is not dict:raise ValueError()
  component=retained.get("component")
  if component is not context.get("qc"):raise ValueError()
  observer=retained.get("navigation_observer")
  if type(observer)is not tuple or len(observer)!=3 or type(observer[0])is not type or type(component)is not observer[0]:raise ValueError()
  stage="original_startup_binding"
  owner=component.owner;scope=component.startup_scope;collection=component.startup_collection
  if owner is not context.get("qo") or scope is not context.get("qs") or collection is not context.get("qz"):raise ValueError()
  owner_module=component.owner_module
  if type(owner_module)is not types.ModuleType:raise ValueError()
  owner_type=owner_module.__dict__.get("FixedStateServiceOwner")
  if type(owner_type)is not type or type(owner)is not owner_type or owner._startup_owner_type_original is not owner_type or owner._startup_namespace_original is not owner_module.__dict__:raise ValueError()
  if scope is not owner.startup_scope or scope is not owner._startup_scope_original or scope.owner is not owner or scope.factory is not owner._startup_factory_original:raise ValueError()
  modules=scope.private_modules;ticket=scope.collector_ticket;startup_module=owner._startup_module_original
  if type(modules)is not dict or modules is not scope._private_modules_original or modules is not context.get("qm"):raise ValueError()
  if type(ticket)is not dict or ticket.get("returned")is not collection or ticket.get("creator")is not owner._startup_collection_type_original:raise ValueError()
  if type(startup_module)is not types.ModuleType or scope.startup_module is not startup_module or startup_module.StartupCollection is not owner._startup_collection_type_original or type(collection)is not startup_module.StartupCollection:raise ValueError()
  if collection is not context.get("inner_collection") or collection.scope is not scope or collection._scope_original is not scope or collection.modules is not modules or collection._modules_original is not modules:raise ValueError()
  originals=scope.module_originals
  if type(originals)is not tuple or len(originals)>64:raise ValueError()
  baseline=modules.get("mta_client_baseline");proc=modules.get("mta_client_proc");core=modules.get("mta_p2p_client_init")
  for name,module in (("mta_client_baseline",baseline),("mta_client_proc",proc),("mta_p2p_client_init",core)):
   if type(module)is not types.ModuleType:raise ValueError()
   rows=[r for r in originals if type(r)is tuple and len(r)==3 and r[0]==name]
   if len(rows)!=1 or rows[0][1]is not module or rows[0][2]is not module.__dict__:raise ValueError()
  if baseline is not context.get("qb") or proc is not context.get("qp") or core is not context.get("qa") or baseline.proc is not proc or baseline.core is not core or proc.owner is not core:raise ValueError()
  definitions=collection._definitions;collector=collection.collector;collector_type=baseline.BaselineCollector
  if type(definitions)is not tuple or len(definitions)!=23 or definitions is not context.get("qd") or definitions[0]is not collector_type or definitions[1]is not collector_type.collect or definitions[4]is not proc.ProcReader or definitions[17]is not proc.ProcReader.__init__:raise ValueError()
  if collector is not context.get("qk") or collector is not collection._collector_original or type(collector)is not collection._native_class or collection._native_class.__bases__!=(collector_type,):raise ValueError()
  for function in (collector_type.collect,collector_type._proc):
   if type(function)is not types.FunctionType or function.__globals__ is not baseline.__dict__:raise ValueError()
  if collector_type._proc.__code__.co_firstlineno!=187:raise ValueError()
  reader=collector._reader;observation=context.get("qv");observations=collector._observations
  if reader is not context.get("qr") or type(reader)is not proc.ProcReader or type(collection.reader_rows)is not list or len(collection.reader_rows)>32:raise ValueError()
  if sum(type(r)is dict and r.get("value")is reader and r.get("bound")is True for r in collection.reader_rows)!=1:raise ValueError()
  if type(observations)is not list or not 1<=len(observations)<=8320 or observations[-1]is not observation or type(observation)is not proc.ProcObservation:raise ValueError()
  inner_error=context.get("inner_error")
  if not isinstance(inner_error,BaseException):raise ValueError()
  tb=inner_error.__traceback__;walked=0;proc_frames=0
  while tb is not None and walked<64:
   frame=tb.tb_frame
   if frame.f_globals is baseline.__dict__ and frame.f_code is collector_type._proc.__code__:
    local=frame.f_locals
    if local.get("self")is not collector or local.get("value")is not observation or local.get("expected")is not context.get("qx") or type(local.get("single"))is not bool or local.get("single")is not context.get("qsingle"):raise ValueError()
    proc_frames+=1
   walked+=1;tb=tb.tb_next
  if tb is not None or proc_frames!=1:raise ValueError()
  stage="original_proc_source"
  proc_namespace=proc.__dict__
  for name,method_name,line in (("ProcReadError","__init__",42),("RawRecord","__init__",106),("StatIdentity","stable_key",120),("ProcObservation","__init__",171),("ProcGeneration","__init__",192),("ProcOpenTicket","__init__",205),("ProcReader","__init__",229)):
   cls=proc_namespace.get(name)
   if type(cls)is not type or cls.__module__!=proc_namespace.get("__name__"):raise ValueError()
   function=cls.__dict__.get(method_name)
   if type(function)is not types.FunctionType or function.__globals__ is not proc_namespace or function.__code__.co_firstlineno!=line:raise ValueError()
  actor_pass=proc.ProcReader.__dict__.get("_actor_pass");observe_body=proc.ProcReader.__dict__.get("_observe_body");fail=proc_namespace.get("_fail")
  for function,line in ((actor_pass,484),(observe_body,606),(fail,47)):
   if type(function)is not types.FunctionType or function.__globals__ is not proc_namespace or function.__code__.co_firstlineno!=line:raise ValueError()
  stage="ended_generation"
  if reader._active is not False or reader._history_active is not False or reader._pending is not False or reader._current_generation is not None or reader._resource_error_v24 is not None:raise ValueError()
  history=reader._history
  if type(history)is not list or not 1<=len(history)<=8320:raise ValueError()
  generation=history[-1]
  if type(generation)is not proc.ProcGeneration or generation.reader is not reader or generation._issuer is not reader._issuer or type(generation.ordinal)is not int or generation.ordinal!=len(history)-1 or generation.observation is not observation:raise ValueError()
  if generation.ended is not True or generation.active is not False or generation.unknown is not False or generation.late is not False:raise ValueError()
  if generation.budget is not reader._bound_budget_v24 or reader._bound_budget_v24 is None or reader._resource_budget_v24 is not reader._bound_budget_v24:raise ValueError()
  if observation.resource_pending is not False or type(observation.file_count)is not int or not 0<=observation.file_count<=280 or type(observation.closed_count)is not int or observation.closed_count!=observation.file_count:raise ValueError()
  if type(observation.reason)is not str:raise ValueError()
  if observation.reason!="pid_identity_changed":
   other_error=generation.error
   if type(other_error)is proc.ProcReadError and other_error.__dict__.get("code")=="pid_identity_changed":raise ValueError()
   return ("not_applicable","no_original_pid_identity_failure",None)
  if observation.kind!="unknown" or observation.stage!="pid_stat" or type(observation.passes)is not int or observation.passes not in (0,1):raise ValueError()
  stage="original_closed_tickets"
  tickets=generation.tickets
  if type(tickets)is not list or len(tickets)!=observation.file_count or not 1<=len(tickets)<=280 or reader._files!=observation.file_count or reader._closed!=observation.closed_count or reader._open_attempt is not None:raise ValueError()
  for ordinal,opened in enumerate(tickets):
   if type(opened)is not proc.ProcOpenTicket or opened.reader is not reader or opened.generation is not generation or opened._issuer is not reader._issuer or type(opened.ordinal)is not int or opened.ordinal!=ordinal or opened.fs is not reader._os:raise ValueError()
   if opened.open_called is not True or opened.returned is not True or opened.registered is not True or opened.failed_without_fd is not False or opened.unknown is not False or opened.open_error is not None or opened.error is not None:raise ValueError()
   if type(opened.descriptor)is not int or not 0<=opened.descriptor<=2147483647 or opened.close_attempted is not True or opened.close_returned is not True or opened.close_result is not None or opened.close_error is not None or opened.close_readback is not None:raise ValueError()
   if opened.ebadf_observed is not True or type(opened.ebadf_errno)is not int or opened.ebadf_errno!=9 or not isinstance(opened.ebadf_error,OSError) or type(opened.ebadf_error.errno)is not int or opened.ebadf_error.errno!=9:raise ValueError()
  stage="original_identity_traceback"
  error=generation.error
  if type(error)is not proc.ProcReadError or type(error.__dict__)is not dict or error.__dict__.get("code")!="pid_identity_changed" or error.args!=("pid_identity_changed",):raise ValueError()
  tb=error.__traceback__;walked=0;actor_local=None;body_local=None;fail_bound=False
  while tb is not None and walked<64:
   frame=tb.tb_frame
   if frame.f_globals is proc_namespace and frame.f_code is actor_pass.__code__:
    if actor_local is not None or tb.tb_lineno!=524 or frame.f_locals.get("self")is not reader:raise ValueError()
    actor_local=frame.f_locals
   if frame.f_globals is proc_namespace and frame.f_code is observe_body.__code__:
    if body_local is not None or frame.f_locals.get("self")is not reader:raise ValueError()
    body_local=frame.f_locals
   if frame.f_globals is proc_namespace and frame.f_code is fail.__code__:
    if fail_bound or tb.tb_lineno!=48 or frame.f_locals.get("code")!="pid_identity_changed":raise ValueError()
    fail_bound=True
   walked+=1;tb=tb.tb_next
  if tb is not None or actor_local is None or body_local is None or fail_bound is not True:raise ValueError()
  stage="finite_cached_stat"
  first=actor_local.get("first");last=actor_local.get("last");leader=actor_local.get("leader")
  identities=(first,last,leader)
  for identity in identities:
   if type(identity)is not proc.StatIdentity:raise ValueError()
   if type(identity.pid)is not int or not 1<=identity.pid<=2147483647 or type(identity.start)is not int or not 1<=identity.start<=18446744073709551615:raise ValueError()
   if type(identity.state)is not str or identity.state not in ("R","S","D","T","t","Z","X","I","P") or type(identity.comm)is not bytes or len(identity.comm)>15 or b"\\0"in identity.comm:raise ValueError()
   if type(identity.flags)is not int or not 0<=identity.flags<=4294967295 or type(identity.ppid)is not int or not 0<=identity.ppid<=2147483647:raise ValueError()
   if type(identity.threads)is not int or not 0<=identity.threads<=128 or identity.threads==0 and identity.state not in ("Z","X"):raise ValueError()
  pid=actor_local.get("pid");root=actor_local.get("root");tids=actor_local.get("tids");directory=actor_local.get("directory");tasks=actor_local.get("tasks")
  if type(pid)is not int or not 1<=pid<=2147483647 or any(identity.pid!=pid for identity in identities) or first.start!=last.start or first.start!=leader.start:raise ValueError()
  if type(root)is not str or root!="/proc/"+str(pid) or type(tids)is not tuple or not 1<=len(tids)<=128 or type(tasks)is not list or len(tasks)!=len(tids):raise ValueError()
  if any(type(tid)is not int or not 1<=tid<=2147483647 for tid in tids) or any(tids[index-1]>=tids[index]for index in range(1,len(tids))) or pid not in tids:raise ValueError()
  if any(type(task)is not proc.StatIdentity for task in tasks) or sum(task is leader for task in tasks)!=1:raise ValueError()
  if type(directory)is not tuple or len(directory)!=6 or any(type(value)is not int or value<0 for value in directory):raise ValueError()
  index=body_local.get("index")
  if type(index)is not int or index not in (1,2) or observation.passes!=index-1 or body_local.get("pid")!=pid or body_local.get("absence_boot")is not None:raise ValueError()
  if body_local.get("expected")is not context.get("qx"):raise ValueError()
  stage="cached_directory_record"
  raw=generation.raw;observed_raw=observation.raw
  if type(raw)is not list or not 1<=len(raw)<=4096 or type(observed_raw)is not tuple or len(observed_raw)!=len(raw) or any(a is not b for a,b in zip(raw,observed_raw)):raise ValueError()
  matches=[]
  for record in raw:
   if type(record)is not proc.RawRecord or type(record.stage)is not str or type(record.pass_index)is not int or record.pass_index not in (0,1,2) or type(record.path)is not str or not 1<=len(record.path)<=4096:raise ValueError()
   if record.stage=="pid_stat" and record.pass_index==index and record.path==root and record.data is None:
    metadata=record.metadata
    if type(metadata)is not tuple or len(metadata)!=6 or any(type(value)is not int or value<0 for value in metadata):raise ValueError()
    matches.append(metadata)
  if len(matches)>1:raise ValueError()
  directory_equal=matches[0]==directory if matches else None
  # Builtin comparisons of the retained fields only, not stable_key or guard calls.
  names=("pid","start","comm","flags","ppid")
  first_last=tuple(getattr(first,name)==getattr(last,name)for name in names)
  first_leader=tuple(getattr(first,name)==getattr(leader,name)for name in names)
  last_threads=last.threads in (0,len(tids))
  flags_xor=(first.flags^last.flags,first.flags^leader.flags)
  row=("receive-startup-proc-identity-diff-v1",first_last,first_leader,last_threads,flags_xor,directory_equal)
  return ("data","finite_cached_identity",row)
 except BaseException:
  return ("unknown",stage,None)
try:
 proc_identity_diff_status,proc_identity_diff_stage,proc_identity_diff_row=_receive_startup_proc_identity_diff_v1(worker,globals())
 if proc_identity_diff_status=="data":
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_IDENTITY_DIFF="+repr(proc_identity_diff_row)+"\\n")
 elif proc_identity_diff_status=="not_applicable":
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_IDENTITY_DIFF_NOT_APPLICABLE="+proc_identity_diff_stage+"\\n")
 else:
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_IDENTITY_DIFF_UNKNOWN="+repr(proc_identity_diff_stage)+"\\n")
 sys.stderr.flush()
except BaseException:
 try:sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_IDENTITY_DIFF_UNKNOWN='projection_output'\\n");sys.stderr.flush()
 except BaseException:pass
'''

DIAGNOSTIC_RAW = TARGET_FRAGMENT


def source_facts():
    """Parse only; never execute the fragment or import historical runtime."""
    ast.parse(TARGET_FRAGMENT.decode('ascii'),
              filename='<receive-startup-proc-identity-diff-v1>', feature_version=(3, 5))
    if not 0 < len(TARGET_FRAGMENT) <= 16384:
        raise ValueError('projection_budget')
    return dict(mode='source-only', target_executed=False, device=False,
                target_bytes=len(TARGET_FRAGMENT),
                target_sha256=hashlib.sha256(TARGET_FRAGMENT).hexdigest(),
                traceback_limit=64, generation_limit=8320, ticket_limit=280,
                raw_record_limit=4096, retained_generation='history[-1]',
                pure_function=True, output='private-bounded-data', admission=False,
                new_clock=False, resource_io=False, original_guard_called=False)


def main():
    print(json.dumps(source_facts(), sort_keys=True))


if __name__ == '__main__':
    main()
