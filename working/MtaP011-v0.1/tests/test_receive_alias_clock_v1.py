"""One affected HOST component contract. No graph execution/device/RF authority."""
import ast
import math
from pathlib import Path
import stat
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/formal-receive-alias-clock-v1/runtime/mta_client_receive_factory.py'
F_SOURCE = BASE / 'candidate/formal-receive-alias-clock-v1/runtime/mta_client_executor.py'


class AliasClockContract(unittest.TestCase):
    def test_actual_guard_refusal_boundary_density_and_private_io_full_check(self):
        tree = ast.parse(SOURCE.read_text(encoding='ascii'))
        classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
        methods = {node.name: node for node in classes['_PublicationAttempt'].body if isinstance(node, ast.FunctionDef)}
        class Rejected(ValueError): pass
        def fail(code): raise Rejected(code)
        class Node: pass
        class State(Node): pass
        class Operation(Node): pass
        class Session(Node): pass
        class Crypto(Node): pass
        class Key(Node): pass
        class Owner(Node): pass
        class Trial(Node): pass
        class ReadOwner(Node):
            def check(self): return self.clock()
            def _fixed_tmp_alias(self): return ()
        def init(self): pass
        calls = dict(full=0, pure=0, guard=0, replaced=0)
        def originals(self):
            calls['pure'] += 1
            if (self.files is not None and hasattr(self.files, 'alias_owner') and
                    self.files.alias_owner.clock is not self._alias_clock):
                fail('publication_owner_changed')
        def now(self):
            calls['full'] += 1
            if getattr(self, 'boundary_rejected', False): fail('publication_owner_changed')
            return self.clock()
        ns = dict(_fail=fail, _number=lambda v: type(v) in (int,float) and math.isfinite(v) and 0 <= v < 1e12)
        code = compile(ast.Module(body=[methods['alias_now']], type_ignores=[]), str(SOURCE), 'exec')
        exec(code, ns)
        Attempt = type('_PublicationAttempt', (), dict(__init__=init, originals=originals, now=now, alias_now=ns['alias_now']))
        service, trials = types.ModuleType('mta_service'), types.ModuleType('mta_receive_trial')
        def authorized(*unused): return True
        authorized.__globals__['contract_service'] = service
        # Real source uses exact canonical globals identity; define the fixture function there.
        exec('def allowed(*unused): return True', service.__dict__)
        service.State, service.Operation, service.ReceiveConnectHandoff = State, Operation, Node
        State._receive_handoff_data_allowed = service.allowed
        trials.FixedReceiveTrial = Trial
        executor = Node(); executor._ReadOwner = ReadOwner
        handoffs = Node(); handoffs.sessions = Node(); handoffs.sessions.TransferSession = Session
        handoffs.crypto = Node(); handoffs.crypto.OpenSslCrypto, handoffs.crypto.KeyPair = Crypto, Key
        functions = (init, originals, now, Attempt.alias_now, ReadOwner.check, ReadOwner._fixed_tmp_alias)
        ns.update(_PublicationAttempt=Attempt, _PUBLICATION_ALIAS_ORIGINALS=functions,
                  _PUBLICATION_ALIAS_CODES=tuple(f.__code__ for f in functions),
                  executor=executor, handoffs=handoffs, _HANDOFF_TYPE=Node)
        saved = {name: sys.modules.get(name) for name in ('mta_service','mta_receive_trial')}
        sys.modules.update(mta_service=service, mta_receive_trial=trials)
        a = Attempt(); state, op, session, h, trial, owner, helper, key, crypto, factory = (
            State(),Operation(),Session(),Node(),Trial(),Owner(),Node(),Key(),Crypto(),Node())
        clock = lambda: 10.0
        worker = threading.current_thread(); reader = threading.Thread()
        cancelled, session_cancelled = threading.Event(), threading.Event()
        lock = threading.RLock()
        a.factory,a.state,a.operation,a.session,a.handoff = factory,state,op,session,h
        a._alias_trial,a._alias_owner,a._alias_lock = trial,owner,lock
        a._alias_functions,a._alias_codes = functions,ns['_PUBLICATION_ALIAS_CODES']
        factory._alias_functions,factory._alias_codes = functions,a._alias_codes
        a._alias_clock = a.alias_now; a.files = None
        a._alias_refs = (helper,key,crypto,reader,cancelled,session_cancelled)
        a.clock,a.worker,a.epoch = clock,worker,1
        a.until=a.original_until=a.handoff_until=a.session_until=50.0
        a.prepare_until=a.original_prepare_until=40.0
        a.last = None
        state.lock,state.operation,state.session,state.worker = lock,op,session,worker
        state.helper,state.key,state.crypto,state.native_epoch,state.closing = helper,key,crypto,1,False
        state._receive_trial=state._receive_trial_original=trial
        op.session,op.receive_trial,op.helper,op.key,op.crypto = session,trial,helper,key,crypto
        op.kind,op.consent,op.epoch,op.cancelled = 'receive',True,1,cancelled
        session._worker,session.cancelled,session._task_deadline = worker,session_cancelled,50.0
        h.helper,h.key,h.crypto,h.reader = helper,key,crypto,reader
        h._failed=h._cancelled=False
        h.clock=h._clock_original=clock; h.deadline=h._deadline_original=50.0
        h._data_authorizer_original=service.allowed;h._last=None
        helper.thread,helper.closed = reader,False
        crypto._lib=Node();key._owner=crypto._lib;key.closed=False
        trial.owner=trial._owner_original=owner;trial.state=state;trial.factory=factory
        trial.until=trial._until_original=80.0;trial.clock=clock;trial.revoked=trial.expired=False
        trial._last=9.0;trial._owner_type=Owner
        owner._startup_namespace_original=trial._owner_namespace={'FixedStateServiceOwner':Owner}
        owner.receive_trial=owner._receive_trial_original=trial
        owner.state,owner.factory,owner.original_until,owner.clock = state,factory,trial.until,clock
        owner.stop_called=owner.close_called=False
        try:
            self.assertEqual(a.alias_now(),10.0)
            self.assertEqual((a.last,h._last,trial._last),(10.0,10.0,9.0))
            def injected(self): calls['replaced'] += 1
            a._alias_functions = (init,injected,now,Attempt.alias_now,ReadOwner.check,ReadOwner._fixed_tmp_alias)
            with self.assertRaises(Rejected): a.alias_now()
            self.assertEqual(calls['replaced'],0);a._alias_functions=functions
            previous=Attempt.alias_now;Attempt.alias_now=injected
            with self.assertRaises(Rejected): previous(a)
            self.assertEqual(calls['replaced'],0);Attempt.alias_now=previous
            negatives = ((trial,'revoked',True),(trial,'expired',True),(owner,'stop_called',True),
                (owner,'close_called',True),(state,'closing',True),(op,'session',Session()),
                (op,'epoch',2),(h,'helper',Node()),(a,'prepare_until',10.0),(a,'last',11.0))
            for obj,attr,value in negatives:
                before=getattr(obj,attr);setattr(obj,attr,value)
                with self.assertRaises(Rejected): a.alias_now()
                setattr(obj,attr,before)
            cancelled.set()
            with self.assertRaises(Rejected): a.alias_now()
            cancelled.clear()
            # Actual metadata alias algorithm, not production graph/FD operations.
            ftree=ast.parse(F_SOURCE.read_text(encoding='ascii'))
            read=next(n for n in ftree.body if isinstance(n,ast.ClassDef) and n.name=='_ReadOwner')
            keep=[n for n in read.body if isinstance(n,ast.FunctionDef) and n.name in ('__init__','check','_fixed_tmp_alias')]
            rns=dict(_fail=fail, _finite=lambda v,*unused: type(v) in (int,float) and math.isfinite(v),
                _uint=lambda v: type(v) is int and v>=0,stat=stat)
            def meta(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime)
            rns['_meta']=meta
            exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(name='_ReadOwner',bases=[],keywords=[],body=keep,decorator_list=[])],type_ignores=[])),str(F_SOURCE),'exec'),rns)
            ActualRead=rns['_ReadOwner'];executor._ReadOwner=ActualRead
            functions=(init,originals,now,Attempt.alias_now,ActualRead.check,ActualRead._fixed_tmp_alias)
            ns['_PUBLICATION_ALIAS_ORIGINALS']=a._alias_functions=factory._alias_functions=functions
            ns['_PUBLICATION_ALIAS_CODES']=a._alias_codes=factory._alias_codes=tuple(f.__code__ for f in functions)
            links={'/tmp':'/var/tmp','/var/tmp':'/var/volatile/tmp'}
            events=[]
            class Io:
                def stat(self,path):
                    events.append(('stat',path))
                    mode=stat.S_IFLNK|0o777 if path in links else stat.S_IFDIR|(0o1777 if path in ('/var/volatile','/var/volatile/tmp') else 0o755)
                    if path.startswith('/var/volatile/tmp/p011-mta-formal-receive-alias-clock-v1'):mode=stat.S_IFDIR|0o700
                    out=Node();out.st_dev=1;out.st_ino=hash(path)&0xffff;out.st_mode=mode
                    out.st_uid=out.st_gid=0;out.st_nlink=1;out.st_size=len(links.get(path,''));out.st_mtime=1
                    out.st_mtime_ns=out.st_ctime_ns=1
                    return out
                def readlink(self,path):events.append(('readlink',path));return links[path]
            executor._LinuxIo=Io
            executor.RECEIVE_ROOT='/unused'
            executor._meta=meta
            def counted(self):
                calls['guard']+=1
                return previous(self)
            # Count calls outside the trusted helper: ReadOwner clock remains original bound method.
            actual_clock=a._alias_clock
            original_clock=clock
            def counting_clock():
                calls['guard']+=1
                return original_clock()
            a.clock=h.clock=h._clock_original=trial.clock=owner.clock=counting_clock
            file_ns=dict(executor=executor,_PublicationAttempt=Attempt,_StartupReadScope=Node,
                _fail=fail,_path=lambda p:type(p)is str and p.startswith('/'),_metadata=meta,stat=stat,
                _directory_identity=lambda m:m,RECEIVE_ROOT='/unused',MAX_ENTRIES=4096,MAX_IMAGE=16777216,
                ASSET_PHYSICAL_ROOT='/var/volatile/tmp/p011-mta-formal-receive-alias-clock-v1',MAX_PROFILE_FILES=512)
            files=classes['_Files']
            names=('__init__','_alias','anchors','read')
            methods_files=[n for n in files.body if isinstance(n,ast.FunctionDef) and n.name in names]
            # Deliberately failing open proves actual pre-open full boundary and ledger; no real syscall.
            def open_no_io(path,flags):events.append(('open',calls['full']));raise OSError('HOST refusal before actual IO')
            file_ns.update(os=types.SimpleNamespace(open=open_no_io,stat=lambda p,follow_symlinks=False:Io().stat(p),
                O_RDONLY=0,O_NOFOLLOW=0,O_CLOEXEC=0),
                hashlib=__import__('hashlib'))
            exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(name='_Files',bases=[],keywords=[],body=methods_files,decorator_list=[])],type_ignores=[])),str(SOURCE),'exec'),file_ns)
            Files=file_ns['_Files'];f=Files(a);a.files=f
            f.close_row=lambda row:None
            calls['full']=calls['guard']=0
            path='/var/volatile/tmp/p011-mta-formal-receive-alias-clock-v1/runtime35/a.py'
            f.anchors(path)
            self.assertEqual(calls['full'],7)
            self.assertEqual(calls['guard'],30) # 23 alias + 7 original full clock calls.
            calls['full']=calls['guard']=0
            with self.assertRaises(OSError):f.read(path,100,'0'*64,True)
            self.assertEqual(events[-1],('open',9))
            self.assertEqual(len(f.rows),1)
            a.boundary_rejected=True
            before=len(events)
            with self.assertRaises(Rejected):f.read(path,100,'0'*64,True)
            self.assertEqual(len(events),before)
            self.assertEqual(trial._last,9.0)
        finally:
            for name,module in saved.items():
                if module is None:sys.modules.pop(name,None)
                else:sys.modules[name]=module


if __name__ == '__main__':
    unittest.main(verbosity=2)
