"""After INNER_DIAGNOSTIC/cleanup, finite original _proc; no IO/admission."""
import ast
import hashlib
import json

TARGET_FRAGMENT = b'''try:
 import sys,types
 st="binding"
 if inner_bound is not True or not isinstance(inner_error,BaseException):raise ValueError()
 qc=worker._RETAINED["component"]
 qo=qc.owner;qs=qc.startup_scope;qz=qc.startup_collection
 qom=qc.owner_module;qot=qom.FixedStateServiceOwner
 if type(qom)is not types.ModuleType or type(qo)is not qot or qo._startup_owner_type_original is not qot or qo._startup_namespace_original is not qom.__dict__:raise ValueError()
 if qs is not qo.startup_scope or qs is not qo._startup_scope_original or qs.owner is not qo or qs.factory is not qo._startup_factory_original:raise ValueError()
 qm=qs.private_modules;qt=qs.collector_ticket;qsm=qo._startup_module_original
 if type(qm)is not dict or qm is not qs._private_modules_original or type(qt)is not dict or qt.get("returned")is not qz or qt.get("creator")is not qo._startup_collection_type_original:raise ValueError()
 if type(qsm)is not types.ModuleType or qs.startup_module is not qsm or qsm.StartupCollection is not qo._startup_collection_type_original or type(qz)is not qsm.StartupCollection:raise ValueError()
 if qz is not inner_collection or qz.scope is not qs or qz._scope_original is not qs or qz.modules is not qm or qz._modules_original is not qm:raise ValueError()
 qb=qm["mta_client_baseline"];qp=qm["mta_client_proc"];qa=qm["mta_p2p_client_init"]
 if type(qs.module_originals)is not tuple or len(qs.module_originals)>64:raise ValueError()
 for qn,qv in (("mta_client_baseline",qb),("mta_client_proc",qp),("mta_p2p_client_init",qa)):
  if type(qv)is not types.ModuleType or not any(type(r)is tuple and len(r)==3 and r[0]==qn and r[1]is qv and r[2]is qv.__dict__ for r in qs.module_originals):raise ValueError()
 if qb.proc is not qp or qb.core is not qa or qp.owner is not qa:raise ValueError()
 qd=qz._definitions;qbc=qb.BaselineCollector;qk=qz.collector
 if type(qd)is not tuple or len(qd)!=23 or qd[0]is not qbc or qd[1]is not qbc.collect or qd[4]is not qp.ProcReader or qd[17]is not qp.ProcReader.__init__:raise ValueError()
 if qk is not qz._collector_original or type(qk)is not qz._native_class or qz._native_class.__bases__!=(qbc,):raise ValueError()
 cf=qbc.collect;pf=qbc._proc
 for qf in (cf,pf):
  if type(qf)is not types.FunctionType or qf.__globals__ is not qb.__dict__:raise ValueError()
 if pf.__code__.co_firstlineno!=187:raise ValueError()
 qr=qk._reader
 if type(qr)is not qp.ProcReader or type(qz.reader_rows)is not list or len(qz.reader_rows)>32 or sum(type(r)is dict and r.get("value")is qr and r.get("bound")is True for r in qz.reader_rows)!=1:raise ValueError()
 st="original_error";qfound=False
 for qe in (qo.startup_failure,qz.failure):
  if not isinstance(qe,BaseException):continue
  t=qe.__traceback__;w=0
  while t is not None and w<64:
   qfr=t.tb_frame
   if qfr.f_globals is qb.__dict__ and qfr.f_code is cf.__code__ and qfr.f_locals.get("self")is qk and qfr.f_locals.get("error")is inner_error:qfound=True
   w+=1;t=t.tb_next
  if t is not None:raise ValueError()
 if not qfound:raise ValueError()
 st="proc_frame";mm=[];t=inner_error.__traceback__;w=0
 while t is not None and w<64:
  qfr=t.tb_frame
  if qfr.f_globals is qb.__dict__ and qfr.f_code is pf.__code__:
   ql=qfr.f_locals
   if ql.get("self")is not qk:raise ValueError()
   mm.append((ql.get("value"),ql.get("expected"),ql.get("single")))
  w+=1;t=t.tb_next
 if t is not None or len(mm)>1:raise ValueError()
 if not mm:
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_NOT_APPLICABLE=no_proc_frame\\n")
 else:
  qv,qx,qsingle=mm[0];qobs=qk._observations
  if type(qobs)is not list or not 1<=len(qobs)<=8320 or qobs[-1]is not qv or type(qv)is not qp.ProcObservation or type(qsingle)is not bool:raise ValueError()
  if qx is not None and (type(qx)is not qa.Actor or not any(type(r)is qp.ProcObservation and r.actor is qx for r in qobs[:-1])):raise ValueError()
  st="finite_projection"
  qkind=qv.kind if type(qv.kind)is str and qv.kind in ("live_actor","unknown","opaque","absence") else None
  qreasons=qp._CODES|frozenset(("read_unknown","permission_denied","read_errno","interrupted","empty_kernel","empty_user_zombie","empty_user_unknown","kernel_cmdline_unexpected","executable_missing","nonlive_task","unsupported_actor_state","live_actor"))
  qreason=qv.reason if type(qv.reason)is str and qv.reason in qreasons else None
  sv=qv.stage if type(qv.stage)is str and qv.stage in ("not_started","boot","pid_directory","pid_stat","cmdline","executable","task_directory","task_stat","recorded_task","proc_root","identity_compare","observed") else None
  qnums=tuple(v if type(v)is int and 0<=v<=280 else None for v in (qv.file_count,qv.closed_count,qv.passes,qv.task_count))
  a=qv.actor;qae=type(a)is qa.Actor;qxe=type(qx)is qa.Actor
  qlive=all(r[2]not in ("Z","X")for r in a.tasks) if qae else None
  qxlive=all(r[2]not in ("Z","X")for r in qx.tasks) if qxe else None
  qbool=tuple(v if type(v)is bool else None for v in (qv.resource_pending,qv.same_boot,qv.pid_path_absent,qsingle,qae,qxe,qlive,qxlive,qv.passes==2 if type(qv.passes)is int else None,qv.task_count==len(a.tasks) if qae and type(qv.task_count)is int else None))
  qeq=tuple(getattr(a,n)==getattr(qx,n)for n in ("pid","start","exe","argv_sha"))+(tuple(r[:2]for r in a.tasks)==tuple(r[:2]for r in qx.tasks),) if qae and qxe else (None,)*5
  sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC="+repr(((qkind,qreason,sv),qnums,qbool,qeq))+"\\n")
 sys.stderr.flush()
except BaseException:
 try:sys.stderr.write("PRIVATE_RECEIVE_STARTUP_PROC_UNKNOWN="+repr(st)+"\\n");sys.stderr.flush()
 except BaseException:pass
'''
DIAGNOSTIC_RAW = TARGET_FRAGMENT

def source_facts():
    ast.parse(TARGET_FRAGMENT.decode('ascii'), feature_version=(3, 5))
    if len(TARGET_FRAGMENT)>6144: raise ValueError('projection_budget')
    return dict(mode='source-only', admission=False, target_bytes=len(TARGET_FRAGMENT),
                sha256=hashlib.sha256(TARGET_FRAGMENT).hexdigest())

if __name__ == '__main__':
    print(json.dumps(source_facts(), sort_keys=True))
