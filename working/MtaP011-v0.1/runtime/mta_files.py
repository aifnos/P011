"""Opaque file selection confined to the toolbox user directory."""
import os
import stat
import threading
import uuid
import errno
from mta_storage import validate_member_name, _check_no_symlinks

MAX_FILES=256
MAX_TOTAL=512*1024*1024
MAX_SINGLE=256*1024*1024
ALLOWED=('Music','Pictures','Text','GameResources','Screenshots','Exports','Received')
_SELECTION_TOKEN=object()


class _FileResource(object):
    """Registered before open; transfer/close uncertainty never releases refs."""
    def __init__(self,registry):
        self.registry=registry;self.fd=None;self.handle=None;self.close_handle=None
        self.opening=True;self.raw_owned=False;self.claimed=False;self.transfer_unknown=False
        self.attempted=False;self.wrapper_closed=False;self.fd_closed=False
        self.pending=False;self.verified=False
        self._open=os.open;self._fstat=os.fstat;self._raw_close=os.close;self._fdopen=os.fdopen
    def __repr__(self):return '<private file-selection resource>'
    def uncertain(self):
        self.pending=True;self.registry._blocked=True
    def acquire(self,path,flags):
        try:self.fd=self._open(path,flags)
        except OSError as error:
            if type(error.errno) is int and 1<=error.errno<=4095:
                self.opening=False;self.verified=True  # Trusted OS negative open: no returned FD.
            else:self.uncertain()
            raise
        except BaseException:
            self.uncertain();raise
        self.opening=False
        if type(self.fd) is not int or not 0<=self.fd<=0x7fffffff:
            self.uncertain();raise ValueError('Invalid file descriptor result')
        self.raw_owned=True
    def claim(self):
        self.transfer_unknown=True  # Before fdopen can consume/close/reuse raw FD.
        try:
            self.handle=self._fdopen(self.fd,'rb')
            handle=self.handle
            if handle is None:raise ValueError('Invalid read-only file wrapper')
            observed=handle.fileno()
            if type(observed) is not int or observed!=self.fd or handle.closed is not False or \
                    type(handle.mode) is not str or handle.mode!='rb' or \
                    handle.readable() is not True or handle.writable() is not False:
                raise ValueError('Invalid read-only file wrapper')
            self.close_handle=handle.close
            if not callable(self.close_handle):raise ValueError('Invalid read-only file wrapper')
        except BaseException:
            self.uncertain();raise
        self.claimed=True;self.raw_owned=False;self.transfer_unknown=False
        return self.handle
    def close(self):
        if self.verified or self.attempted or self.pending:return
        if self.opening or self.transfer_unknown or not (self.raw_owned or self.claimed):
            self.uncertain();return
        self.attempted=True;returned=False
        try:
            result=self.close_handle() if self.claimed else self._raw_close(self.fd)
            returned=result is None
        except BaseException:
            self.uncertain()
        if self.claimed:
            try:self.wrapper_closed=self.handle.closed is True
            except BaseException:self.uncertain()
        try:self._fstat(self.fd)
        except OSError as error:
            self.fd_closed=type(error.errno) is int and error.errno==errno.EBADF
        except BaseException:pass
        self.verified=bool(returned and self.fd_closed and (not self.claimed or self.wrapper_closed) and not self.pending)
        if not self.verified:self.uncertain()


def _lifecycle(resources,pending=False):
    return {'resource_count':len(resources),'open_attempt_count':len(resources),
        'close_attempted_count':sum(r.attempted for r in resources),
        'wrapper_closed_count':sum(r.wrapper_closed for r in resources),
        'fd_closed_count':sum(r.fd_closed for r in resources),
        'unknown_count':sum(r.pending for r in resources),
        'resource_pending':bool(pending or any(r.pending for r in resources)),
        'closure_verified':bool(not pending and all(r.verified for r in resources))}


class FileSelection(object):
    def __init__(self,entries,_token=None,_registry=None,_resources=None):
        if _token is not _SELECTION_TOKEN or _registry is None or type(_resources) is not list:
            raise ValueError('Use FileRegistry.open_selection')
        self.entries=entries;self.total_bytes=sum(e['size'] for e in entries);self.closed=False
        self._registry=_registry;self._resources=tuple(_resources);self._close_requested=False
    def close(self):
        with self._registry.lock:
            if not self._close_requested:
                self._close_requested=True
                for resource in self._resources:
                    try:resource.close()
                    except BaseException:resource.uncertain()
                self.closed=True  # Selection invalidated, NOT an FD closure proof.
                self._registry._prune()
            if any(r.pending or not r.verified for r in self._resources):
                raise ValueError('File selection resource closure is unverified')
    def lifecycle_status(self):
        with self._registry.lock:
            result=_lifecycle(self._resources)
            result.update(close_requested=self._close_requested,selection_closed=self.closed)
            return result
    def __enter__(self):
        if self.closed or self._close_requested:raise ValueError('File selection is closed')
        return self
    def __exit__(self,*unused):self.close()


def signature(value):
    return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns if hasattr(value,'st_mtime_ns') else value.st_mtime)


class FileRegistry(object):
    def __init__(self,root):
        if not isinstance(root,str) or not os.path.isabs(root) or os.path.dirname(root)==root:
            raise ValueError('Explicit user subdirectory required')
        _check_no_symlinks(root)
        if not os.path.isdir(root):raise ValueError('User directory does not exist')
        self.root=os.path.abspath(root);self.catalog={};self.lock=threading.RLock()
        self._resources=[];self._blocked=False
    def _prune(self):self._resources[:]=[r for r in self._resources if not r.verified]
    def lifecycle_status(self):
        with self.lock:return _lifecycle(self._resources,self._blocked)

    def list_files(self):
        found={}
        with self.lock:
            previous={(v['relative'],v['signature']):k for k,v in self.catalog.items()}
            for category in ALLOWED:
                base=os.path.join(self.root,category)
                if not os.path.isdir(base) or os.path.islink(base):continue
                for directory,dirs,files in os.walk(base,followlinks=False):
                    dirs[:]=[n for n in dirs if not n.startswith('.') and not os.path.islink(os.path.join(directory,n))]
                    if len(os.path.relpath(directory,self.root).split(os.sep))>=12:dirs[:]=[]
                    for name in files:
                        if name.startswith('.'):continue
                        path=os.path.join(directory,name)
                        try:
                            value=os.lstat(path)
                            if not stat.S_ISREG(value.st_mode) or value.st_size>MAX_SINGLE:continue
                            relative=os.path.relpath(path,self.root).replace(os.sep,'/')
                            validate_member_name(relative)
                        except (OSError,ValueError):continue
                        observed=signature(value)
                        key=previous.get((relative,observed)) or uuid.uuid4().hex
                        found[key]={'relative':relative,'signature':observed,'size':value.st_size}
                        if len(found)>=2048:break
                    if len(found)>=2048:break
                if len(found)>=2048:break
            self.catalog=found
            return [{'id':key,'name':row['relative'],'size':row['size']} for key,row in sorted(found.items(),key=lambda pair:pair[1]['relative'])]

    def open_selection(self,ids):
        if not isinstance(ids,list) or not 1<=len(ids)<=MAX_FILES or not all(isinstance(x,str) for x in ids) or len(set(ids))!=len(ids):
            raise ValueError('Invalid file selection')
        entries=[];resources=[]
        with self.lock:
            if self._blocked:raise ValueError('File resource lifecycle is unresolved')
            try:
                for key in ids:
                    row=self.catalog.get(key)
                    if row is None:raise ValueError('Stale file selection')
                    path=os.path.join(self.root,*validate_member_name(row['relative']))
                    _check_no_symlinks(os.path.dirname(path))
                    value=os.lstat(path)
                    if not stat.S_ISREG(value.st_mode) or signature(value)!=row['signature']:
                        raise ValueError('Selected file changed')
                    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)
                    resource=_FileResource(self)
                    self._resources.append(resource);resources.append(resource)
                    resource.acquire(path,flags)
                    try:observed=resource._fstat(resource.fd)
                    except OSError as error:
                        if type(error.errno) is int and error.errno==errno.EBADF:
                            resource.fd_closed=True;resource.uncertain()  # No longer known raw owner; never close a reused number.
                        raise
                    if not stat.S_ISREG(observed.st_mode) or signature(observed)!=row['signature']:
                        raise ValueError('Selected file changed while opening')
                    entries.append({'name':row['relative'],'size':row['size'],'handle':resource.claim()})
                if sum(e['size'] for e in entries)>MAX_TOTAL:raise ValueError('Selected bytes exceed limit')
                return FileSelection(entries,_SELECTION_TOKEN,self,resources)
            except BaseException:
                for resource in resources:
                    try:resource.close()
                    except BaseException:resource.uncertain()
                self._prune()
                raise
