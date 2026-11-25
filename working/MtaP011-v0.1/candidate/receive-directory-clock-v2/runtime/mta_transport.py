# Independent directory-FD candidate. No RF/service admission or deployment.
"""Bounded MTA WSS/HTTPS receive transport, Python 3.5, no third parties.

Original MTA peers use self-signed certificates. Compatibility TLS is encrypted
but is not authenticated against a CA; the first connection certificate is
pinned for this task's download. Never accept an arbitrary endpoint from QML.
"""
import base64
import hashlib
import hmac
import math
import os
import re
import socket
import ssl
import stat
import struct
import tempfile
import threading
import time

from mta_protocol import WsMessage, ProtocolError, validate_send_request
from mta_storage import DirectoryBinding

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MESSAGE = 65536
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
_NO_RAW=object()


class TransportError(RuntimeError):
    pass


class Cancelled(TransportError):
    pass


def _deadline_number(value):
    if (isinstance(value,bool) or not isinstance(value,(int,float)) or
            not math.isfinite(value) or not 0 <= value <= 2 ** 53):
        raise TransportError('Invalid transfer deadline')
    return float(value)


class AbsoluteBudget(object):
    """Trusted internal once-issued end; stage changes cannot renew it."""
    def __init__(self,until,clock=None):
        if clock is not None and not callable(clock):
            raise TransportError('Invalid transfer clock')
        self.until=_deadline_number(until)
        self.clock=clock or time.monotonic
        self.last=None

    def now(self):
        try:value=_deadline_number(self.clock())
        except Exception:raise TransportError('Transfer clock failed')
        if self.last is not None and value < self.last:
            raise TransportError('Transfer clock moved backwards')
        self.last=value
        return value

    def remaining(self,until=None):
        end=self.until if until is None else min(self.until,_deadline_number(until))
        remaining=end-self.now()
        if remaining<=0:raise TransportError('Transfer deadline exceeded')
        return remaining


class SocketLifecycle(object):
    """Private exact-object owner; TLS detach is not socket closure evidence.

    Keep every unresolved create/wrap/start/close actor and actual worker thread.
    A borrowed non-main worker identity remains pending until it really exits;
    completing a function or joining the current thread is not that evidence.
    No paths, peer addresses or exception text appear in the passive snapshot.
    """
    def __init__(self):
        self.lock=threading.RLock()
        self.closing=False
        self._next_actor=0
        self._actors={}
        self._callers=[]
        self._threads=[]
        self._records=[]
        self._unknown_resources=[]
        self._closers={}
        self._processes=[]

    def begin(self,kind):
        with self.lock:
            if self.closing:raise Cancelled('Transfer cancelled')
            thread=threading.current_thread()
            if thread is not threading.main_thread() and all(row is not thread for row in self._callers):
                self._callers.append(thread)
            self._next_actor+=1
            actor=self._next_actor
            self._actors[actor]=(kind,thread)
            return actor

    def end(self,actor):
        with self.lock:self._actors.pop(actor,None)

    def check(self):
        with self.lock:
            if self.closing:raise Cancelled('Transfer cancelled')

    def adopt(self,raw):
        with self.lock:
            if raw is None:raise TransportError('Invalid owned socket')
            if any(row['raw'] is raw for row in self._records):
                raise TransportError('Duplicate owned socket')
            row={'raw':raw,'tls':None,'wrapping':False,'unknown_wrap':False,
                 'transferred':False,'raw_closed':False,'tls_closed':False,
                 'raw_uncertain':False,'tls_uncertain':False}
            self._records.append(row)
            return row

    def adopt_returned(self,raw):
        # A malformed factory result can still own a resource. Never discard
        # it merely because it is not a socket or has no usable fd readback.
        try:usable=callable(getattr(raw,'close',None)) and callable(getattr(raw,'fileno',None))
        except Exception:usable=False
        if usable:
            self.adopt(raw)
            return True
        with self.lock:
            if all(value is not raw for value in self._unknown_resources):self._unknown_resources.append(raw)
        self._close_unknown(raw)
        return False

    @staticmethod
    def _close_unknown(raw):
        try:raw.close()
        except Exception:pass
        # No fd/type/closure contract: a returning close() is not evidence.

    def _record(self,handle):
        if handle is None:return None
        for row in self._records:
            if row['raw'] is handle or row['tls'] is handle:return row
        return None

    def begin_wrap(self,raw):
        with self.lock:
            self.check()
            row=self._record(raw)
            if row is None or row['tls'] is not None or row['wrapping'] or row['raw_closed']:
                raise TransportError('Invalid owned TLS transition')
            row['wrapping']=True

    def finish_wrap(self,raw,tls):
        # Even after cancellation, retain the exact late TLS wrapper before
        # closing it. The raw fd may already have been detached during wrap.
        with self.lock:
            row=self._record(raw)
            if row is None or not row['wrapping'] or tls is raw:
                raise TransportError('Invalid owned TLS wrapper')
            row['tls']=tls
            row['wrapping']=False
            try:row['transferred']=raw.fileno()==-1
            except Exception:row['unknown_wrap']=True
            if row['transferred']:row['raw_uncertain']=False

    def failed_wrap(self,raw):
        with self.lock:
            row=self._record(raw)
            if row is None:return
            row['wrapping']=False
            try:detached=raw.fileno()==-1
            except Exception:detached=True
            # No wrapper was returned: there is no exact wrapper to prove
            # closed, even if the SSL implementation normally cleans errors.
            if detached:row['unknown_wrap']=True

    def close_socket(self,handle):
        with self.lock:
            row=self._record(handle)
            if row is None:return False
            tls=row['tls'] is handle
            name='tls' if tls else 'raw'
            if row[name+'_closed']:return True
            if not tls and row['transferred']:return row['tls_closed'] and not row['wrapping']
            if id(handle) in self._closers:return False
            self._closers[id(handle)]=handle
        verified=False
        uncertain=False
        try:
            try:before=handle.fileno()
            except Exception:before=None
            if type(before) is not int or before<0:uncertain=True
            try:handle.shutdown(socket.SHUT_RDWR)
            except Exception:pass
            try:
                handle.close()
                after=handle.fileno()
                verified=not uncertain and type(after) is int and after==-1
            except Exception:pass
        finally:
            with self.lock:
                self._closers.pop(id(handle),None)
                row[name+'_closed']=row[name+'_closed'] or verified
                row[name+'_uncertain']=row[name+'_uncertain'] or uncertain
        return verified

    def start_thread(self,thread):
        with self.lock:
            self.check()
            row={'thread':thread,'starting':True,'start_resolved':False,'started':False}
            self._threads.append(row)
        try:
            thread.start()
            with self.lock:row['started']=True
        finally:
            with self.lock:
                row['starting']=False
                row['start_resolved']=True

    def adopt_process(self,process):
        with self.lock:self._processes.append(process)

    def _processes_pending(self):
        count=0
        for process in self._processes:
            try:pending=process.poll() is None
            except Exception:pending=True
            count+=pending
        return count

    @staticmethod
    def _alive(thread):
        try:return thread.is_alive() is not False
        except Exception:return True

    def _pending_threads(self,ignore_thread=None):
        result=[]
        for row in self._threads:
            thread=row['thread']
            if thread is ignore_thread:continue
            if row['starting'] or not row['start_resolved'] or self._alive(thread):
                if all(item is not thread for item in result):result.append(thread)
        for thread in self._callers:
            if thread is not ignore_thread and self._alive(thread) and all(item is not thread for item in result):
                result.append(thread)
        return result

    def request_close(self):
        with self.lock:self.closing=True

    @staticmethod
    def _record_closed(row):
        if row['wrapping'] or row['unknown_wrap']:return False
        raw_closed=row['raw_closed'] or (row['transferred'] and row['tls_closed'])
        return raw_closed and (row['tls'] is None or row['tls_closed'])

    def close(self,timeout=2):
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 0<=timeout<=2:
            raise TransportError('Invalid close budget')
        self.request_close()
        deadline=time.monotonic()+min(2,max(0,timeout))
        with self.lock:
            handles=[]
            for row in self._records:
                if row['tls'] is not None:handles.append(row['tls'])
                if not row['transferred']:handles.append(row['raw'])
        # One close failure never skips any other owned resource.
        for handle in handles:self.close_socket(handle)
        with self.lock:unknown=list(self._unknown_resources)
        for handle in unknown:self._close_unknown(handle)
        with self.lock:threads=self._pending_threads()
        for thread in threads:
            if thread is threading.current_thread():continue
            remaining=deadline-time.monotonic()
            if remaining<=0:break
            try:thread.join(remaining)
            except (RuntimeError,ValueError):pass
        return self.snapshot()['close_verified']

    def cleanup_ready(self,ignore_thread=None):
        # Function-tail cleanup can ignore ONLY that current finishing thread;
        # closure_snapshot/closed NEVER ignore its still-live identity.
        with self.lock:
            return (self.closing and not self._actors and not self._closers and
                    not self._pending_threads(ignore_thread) and not self._processes_pending() and
                    not self._unknown_resources and
                    all(self._record_closed(row) for row in self._records))

    def actors_quiet(self,ignore_thread=None):
        with self.lock:
            return (self.closing and not self._actors and not self._pending_threads(ignore_thread)
                    and not self._processes_pending())

    def snapshot(self,raw=_NO_RAW):
        with self.lock:
            sockets_pending=sum(not self._record_closed(row) for row in self._records)+len(self._unknown_resources)
            threads_pending=len(self._pending_threads())
            actors_pending=len(self._actors)+len(self._closers)
            processes_pending=self._processes_pending()
            complete=(self.closing and not sockets_pending and not threads_pending and
                      not actors_pending and not processes_pending)
            result={'closing':self.closing,'socket_records':len(self._records),
                'sockets_pending':sockets_pending,'actors_pending':actors_pending,
                'threads_pending':threads_pending,'wrappers_pending':sum(row['wrapping'] for row in self._records),
                'unknown_wrappers':sum(row['unknown_wrap'] for row in self._records),
                'unknown_resources':len(self._unknown_resources),
                'processes_pending':processes_pending,
                'close_verified':complete}
            if raw is not _NO_RAW:
                result.update({'recognized_raw':any(row['raw'] is raw for row in self._records),
                    'all_sockets_closed':sockets_pending==0,
                    'all_actors_exited':actors_pending==0 and threads_pending==0 and processes_pending==0})
            return result


def private_ipv4(host):
    if not isinstance(host,str) or re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',host) is None:
        raise TransportError('Only a verified private IPv4 endpoint is allowed')
    parts=[int(part) for part in host.split('.')]
    if any(part>255 for part in parts) or host!='.'.join(str(part) for part in parts):
        raise TransportError('Invalid IPv4 endpoint')
    if not (parts[0]==10 or parts[:2]==[192,168] or (parts[0]==172 and 16<=parts[1]<=31)) or parts[3] in (0,255):
        raise TransportError('Endpoint is not a private unicast address')
    return host


class Stream(object):
    def __init__(self,sock,cancelled=None,deadline=None,initial=b'',clock=None):
        self.socket=sock
        self.cancelled=cancelled or (lambda:False)
        timer=clock or time.monotonic
        self.deadline=_deadline_number(timer()+180 if deadline is None else deadline)
        self._budget=AbsoluteBudget(self.deadline,timer)
        self.buffer=initial
        self.check()
        self.socket.settimeout(min(.5,self._budget.remaining(self.deadline)))

    def check(self):
        if self.cancelled():raise Cancelled('Transfer cancelled')
        self._budget.remaining(self.deadline)

    def _before_io(self):
        self.check()
        self.socket.settimeout(min(.5,self._budget.remaining(self.deadline)))
        self.check()

    def read(self,size):
        self.check()
        result=self.buffer[:size];self.buffer=self.buffer[size:]
        while len(result)<size:
            self._before_io()
            try:block=self.socket.recv(min(65536,size-len(result)))
            except socket.timeout:continue
            self.check()
            if not block:raise TransportError('Unexpected end of transfer')
            result+=block
        self.check();return result

    def line(self,limit=4096):
        while b'\r\n' not in self.buffer:
            self._before_io()
            if len(self.buffer)>limit:raise TransportError('HTTP line limit')
            try:block=self.socket.recv(4096)
            except socket.timeout:continue
            self.check()
            if not block:raise TransportError('Unexpected end of HTTP headers')
            self.buffer+=block
        line,self.buffer=self.buffer.split(b'\r\n',1)
        if len(line)>limit:raise TransportError('HTTP line limit')
        self.check();return line

    def send(self,data):
        offset=0
        while offset<len(data):
            self._before_io()
            try:sent=self.socket.send(data[offset:offset+65536])
            except socket.timeout:continue
            self.check()
            if sent<=0:raise TransportError('Transfer socket closed')
            offset+=sent


def read_headers(stream):
    first=stream.line()
    headers={};size=len(first)+2
    for _ in range(80):
        line=stream.line()
        size+=len(line)+2
        if size>16384:raise TransportError('HTTP header limit')
        if not line:return first,headers
        if b':' not in line or line[:1] in (b' ',b'\t'):raise TransportError('Invalid HTTP header')
        key,value=line.split(b':',1)
        if re.match(br'^[A-Za-z0-9-]+$',key) is None:raise TransportError('Invalid HTTP header name')
        try:key=key.decode('ascii').lower();value=value.strip().decode('ascii')
        except UnicodeError:raise TransportError('Invalid HTTP header encoding')
        if key in headers or any(ord(c)<32 or ord(c)==127 for c in value):
            raise TransportError('Ambiguous HTTP header')
        headers[key]=value
    raise TransportError('HTTP header count limit')


class WebSocket(object):
    def __init__(self,stream,client=True):
        self.stream=stream;self.client=client

    def frame(self,opcode,payload):
        if len(payload)>MAX_MESSAGE or (opcode>=8 and len(payload)>125):
            raise TransportError('WebSocket message limit')
        header=bytearray([0x80|opcode])
        maskbit=0x80 if self.client else 0
        if len(payload)<126:header.append(maskbit|len(payload))
        else:header.append(maskbit|126);header.extend(struct.pack('!H',len(payload)))
        if self.client:
            mask=os.urandom(4);header.extend(mask)
            payload=bytes(bytearray(b^mask[i%4] for i,b in enumerate(payload)))
        self.stream.send(bytes(header)+payload)

    def send(self,message):
        text=message.serialize() if isinstance(message,WsMessage) else message
        self.frame(1,text.encode('utf-8'))

    def receive(self):
        message=bytearray();started=False
        for _ in range(128):
            head=self.stream.read(2);final=bool(head[0]&0x80);opcode=head[0]&15
            masked=bool(head[1]&0x80);length=head[1]&127
            if head[0]&0x70 or masked==self.client:raise TransportError('Invalid WebSocket frame')
            if length==126:
                length=struct.unpack('!H',self.stream.read(2))[0]
                if length<126:raise TransportError('Noncanonical frame length')
            elif length==127:
                length=struct.unpack('!Q',self.stream.read(8))[0]
                if length<65536:raise TransportError('Noncanonical frame length')
            if length>MAX_MESSAGE or (opcode>=8 and (not final or length>125)):
                raise TransportError('WebSocket frame limit')
            mask=self.stream.read(4) if masked else None
            payload=self.stream.read(length)
            if mask:payload=bytes(bytearray(b^mask[i%4] for i,b in enumerate(payload)))
            if opcode==8:raise TransportError('Peer closed transfer')
            if opcode==9:self.frame(10,payload);continue
            if opcode==10:continue
            if opcode==1 and not started:started=True
            elif opcode!=0 or not started:raise TransportError('Unexpected WebSocket opcode')
            message.extend(payload)
            if len(message)>MAX_MESSAGE:raise TransportError('WebSocket message limit')
            if final:return WsMessage.parse(bytes(message))
        raise TransportError('WebSocket frame count limit')


def websocket_client(stream,host,port):
    key=base64.b64encode(os.urandom(16)).decode('ascii')
    request=('GET /websocket HTTP/1.1\r\nHost: '+host+':'+str(port)+'\r\n'+
             'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'+
             'Sec-WebSocket-Key: '+key+'\r\n\r\n')
    stream.send(request.encode('ascii'))
    first,headers=read_headers(stream)
    expected=base64.b64encode(hashlib.sha1((key+WS_GUID).encode('ascii')).digest()).decode('ascii')
    if (re.match(br'^HTTP/1\.[01] 101(?: |$)',first) is None or
        headers.get('upgrade','').lower()!='websocket' or
        'upgrade' not in [v.strip().lower() for v in headers.get('connection','').split(',')] or
        not hmac.compare_digest(headers.get('sec-websocket-accept',''),expected)):
        raise TransportError('WebSocket handshake failed')
    return WebSocket(stream,True)


def download_body(stream,headers,output,maximum=MAX_ARCHIVE,progress=None,space_check=None):
    length=headers.get('content-length');encoding=headers.get('transfer-encoding')
    if length is not None and encoding is not None:raise TransportError('Ambiguous HTTP body')
    total=0
    def chunk(size):
        nonlocal total
        if size>maximum-total:raise TransportError('Archive byte limit')
        while size:
            count=min(size,65536)
            if total+count>maximum:raise TransportError('Archive byte limit')
            if space_check:space_check(count)
            data=stream.read(count);output.write(data);size-=count;total+=count
            if progress:progress(total)
    if encoding is not None:
        if encoding.lower()!='chunked':raise TransportError('Unsupported transfer encoding')
        for _ in range(100000):
            raw=stream.line(128).split(b';',1)[0]
            if re.match(br'^[0-9a-fA-F]{1,16}$',raw) is None:raise TransportError('Invalid chunk size')
            count=int(raw,16)
            if not count:
                # Consume a bounded trailer section; no unbounded peer input.
                for index in range(32):
                    if not stream.line(512):return total
                raise TransportError('HTTP trailer limit')
            chunk(count)
            if stream.read(2)!=b'\r\n':raise TransportError('Invalid chunk terminator')
        raise TransportError('HTTP chunk count limit')
    if length is None or re.match(r'^[0-9]{1,12}$',length) is None:raise TransportError('HTTP body length required')
    count=int(length)
    if count>maximum:raise TransportError('Archive byte limit')
    chunk(count)
    return total


class ReceiverTransport(object):
    def __init__(self,host,port,receiver,cancelled=None,timeout=300,
                 socket_factory=None,source_ip=None,absolute_until=None,clock=None,handoff=None):
        self.host=private_ipv4(host)
        if isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
            raise TransportError('Invalid transfer port')
        self.port=port;self.receiver=receiver
        self.directory_binding=getattr(receiver,'directory_binding',None)
        self._directory_binding_original=self.directory_binding
        if self.directory_binding is not None and (type(self.directory_binding) is not DirectoryBinding or
                self.directory_binding.root != receiver.root):
            raise TransportError('Original receive directory required')
        self._bound_downloads=[]
        self.local_commit_result=None
        if (socket_factory is None) != (source_ip is None) or (socket_factory is not None and not callable(socket_factory)):
            raise TransportError('A scoped connector requires its verified source address')
        if socket_factory is not None and self.directory_binding is None:
            raise TransportError('Scoped receive requires the original directory binding')
        # Internal lease API only. The lease must prove/retain the actual
        # interface and bind the returned socket to it (e.g. SO_BINDTODEVICE).
        # These fields are never accepted as QML/HTTP actions. No factory
        # failure falls back to the original wlan0/default route.
        self.socket_factory=socket_factory
        self.source_ip=private_ipv4(source_ip) if source_ip is not None else None
        if (clock is not None and not callable(clock)) or (handoff is not None and not callable(handoff)):
            raise TransportError('Invalid private transfer owner')
        if socket_factory is not None and absolute_until is None:
            raise TransportError('Scoped transfer requires its original deadline')
        if socket_factory is not None and handoff is None:
            raise TransportError('Scoped transfer requires handoff registration')
        timer=clock or time.monotonic
        started=_deadline_number(timer())
        if absolute_until is None:
            duration=_deadline_number(timeout)
            until=started+min(600,max(15,duration))
        else:
            until=_deadline_number(absolute_until)
            if not 0 < until-started <= 300:
                raise TransportError('Original transfer deadline out of scope')
        if self.directory_binding is not None:
            # Native lease checks wrap monotonic. Keep that original callback
            # and independently check the held directory's own original cap;
            # distinct callables are not distinct monotonic time domains.
            if until > self.directory_binding.absolute_until:
                raise TransportError('Receive directory original deadline exceeded')
            self.directory_binding.check()
        self.deadline=until
        self._budget=AbsoluteBudget(until,timer)
        self._budget.last=started
        self._handoff=handoff
        self._external_cancelled=cancelled or (lambda:False)
        self._cancelled=threading.Event()
        self.cancelled=self._is_cancelled
        self.fingerprint=None
        self._life=SocketLifecycle()
        self._lock=threading.RLock()
        self._run_claimed=False
        self._temporary_paths={}
        self._temporary_fds={}
        self._temporary_outputs=[]
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.verify_mode=ssl.CERT_NONE
        self.context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5:!RC4')

    def _is_cancelled(self):
        if self._cancelled.is_set():return True
        value=self._external_cancelled()
        if type(value) is not bool:raise TransportError('Invalid cancellation result')
        return value or self._budget.now() >= self.deadline

    def _check(self):
        self._life.check()
        if (self.directory_binding is not self._directory_binding_original or
                getattr(self.receiver,'directory_binding',None) is not self._directory_binding_original):
            raise TransportError('Original receive directory binding changed')
        if self.cancelled():raise Cancelled('Transfer cancelled')
        remaining=self._budget.remaining()
        if self.directory_binding is not None:
            if self.directory_binding.root != self.receiver.root:
                raise TransportError('Original receive directory root changed')
            self.directory_binding.check()
        return remaining

    def connect(self):
        actor=self._life.begin('receive_connect')
        raw=None
        sock=None
        try:
            remaining=self._check()
            if self.socket_factory is None:
                raw=socket.create_connection((self.host,self.port),min(3,remaining))
            else:
                raw=self.socket_factory(self.host,self.port,min(3,remaining))
            if not self._life.adopt_returned(raw):
                raise TransportError('Connector returned an unverified resource')
            # Both WSS and download sockets are retained by the coordinator
            # before TLS may detach their raw FD. A failed hook never falls
            # back to the unscoped connector or skips transport cleanup.
            if self._handoff is not None and self._handoff(self,raw) is not raw:
                raise TransportError('Raw handoff registration failed')
            self._life.check()
            if self.socket_factory is not None:
                if (not isinstance(raw,socket.socket) or isinstance(raw,ssl.SSLSocket) or
                        raw.family!=socket.AF_INET or raw.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM):
                    raise TransportError('Scoped connector did not return a raw IPv4 TCP socket')
                if raw.getpeername()!=(self.host,self.port) or raw.getsockname()[0]!=self.source_ip:
                    raise TransportError('Scoped connector address readback mismatch')
            self._check()
            handshake_deadline=min(self.deadline,self._budget.now()+12)
            self._life.begin_wrap(raw)
            try:sock=self.context.wrap_socket(raw,server_hostname=self.host,do_handshake_on_connect=False)
            except BaseException:
                self._life.failed_wrap(raw)
                raise
            self._life.finish_wrap(raw,sock)
            self._life.check()
            while True:
                self._check()
                sock.settimeout(min(.5,self._budget.remaining(handshake_deadline)))
                try:
                    sock.do_handshake()
                    self._budget.remaining(handshake_deadline)
                    self._check();break
                except socket.timeout:continue
            digest=hashlib.sha256(sock.getpeercert(binary_form=True)).digest()
            with self._lock:
                if self.cancelled():raise Cancelled('Transfer cancelled')
                if self.fingerprint is not None and not hmac.compare_digest(digest,self.fingerprint):
                    raise TransportError('Peer certificate changed during task')
                self.fingerprint=digest
            return Stream(sock,self.cancelled,self.deadline,clock=self._budget.now)
        except BaseException:
            if sock is not None:self._life.close_socket(sock)
            if raw is not None:self._life.close_socket(raw)
            self._cancelled.set()
            self._life.close(0)
            raise
        finally:
            self._life.end(actor)
            if self._life.closing:self._cleanup_temporary(threading.current_thread())

    def run(self,confirm,progress=None,file_progress=None):
        actor=self._life.begin('receive_run')
        try:
            with self._lock:
                if self._run_claimed:raise TransportError('Receiver cannot run twice')
                self._run_claimed=True
            return self._run_impl(confirm,progress,file_progress)
        finally:
            self._life.end(actor)
            self._cancelled.set()
            self._life.close(0)
            self._cleanup_temporary(threading.current_thread())

    def _run_impl(self,confirm,progress=None,file_progress=None):
        self._check()
        stream=self.connect();download=None;temporary=None
        try:
            ws=websocket_client(stream,self.host,self.port)
            negotiated=False;request=None
            for _ in range(32):
                message=ws.receive()
                if message.msg_type!='action':raise ProtocolError('Expected action before transfer')
                if message.name=='versionNegotiation' and not negotiated:
                    payload=message.payload or {}
                    version=payload.get('version')
                    versions=payload.get('versions',[])
                    if not isinstance(versions,list) or len(versions)>32 or any(isinstance(v,bool) or not isinstance(v,int) for v in versions):
                        raise ProtocolError('Invalid MTA versions')
                    if isinstance(version,bool) or (version!=1 and 1 not in versions):
                        raise ProtocolError('Unsupported MTA version')
                    ws.send(message.make_ack({'version':1,'threadLimit':1}));negotiated=True
                elif message.name=='sendRequest' and negotiated and request is None:
                    request=validate_send_request(message.payload)
                    accepted=confirm(request)
                    self._check()
                    if type(accepted) is not bool:raise TransportError('Invalid receive confirmation')
                    if not accepted:
                        ws.send(WsMessage('action',1,'status',{'taskId':request['taskId'],'id':request['taskId'],'type':3,'reason':'user refuse'}))
                        raise Cancelled('Transfer refused')
                    ws.send(message.make_ack());break
                else:raise ProtocolError('Unexpected negotiation action')
            if request is None:raise ProtocolError('No send request')
            self._check()
            maximum=min(MAX_ARCHIVE,request['totalSize']+1024*1024)
            self.receiver._space(request['totalSize'])
            self._check()
            # One shared original directory and archive handle for download,
            # metadata bounds, ZIP parsing and commit; no path-based fallback.
            if self.directory_binding is not None:
                row={'resource':None,'close_attempted':False,'closed':False,
                    'remove_attempted':False,'removed':False,'failures':[]}
                self._bound_downloads.append(row)
                try:
                    resource=self.directory_binding.create_download()
                    row['resource']=resource
                except BaseException as failure:
                    # The directory owner retains any partially created
                    # resource. No returned original means this transport
                    # cannot assert closure or unlink a guessed pathname.
                    row['failures'].append(failure)
                    raise
                self._check()
                download=self.connect()
                self._download_into(download,request,resource.handle,maximum,progress)
                result=self.receiver.receive(resource.path,request['taskId'],self.cancelled,
                    progress=file_progress,expected_files=request['fileCount'],
                    expected_bytes=request['totalSize'],archive_resource=resource)
            else:
                # The unbound legacy HOST lane is retained, never used by the
                # bound CLIENT adapter and never selected after bound failure.
                fd,temporary=tempfile.mkstemp(prefix='.mta-download-',suffix='.zip',dir=self.receiver.root)
                with self._lock:
                    self._temporary_paths[temporary]=None
                    self._temporary_fds[temporary]=(fd,None,None)
                    value=os.fstat(fd)
                    if not stat.S_ISREG(value.st_mode):raise TransportError('Temporary archive is not a regular file')
                    self._temporary_fds[temporary]=(fd,value.st_dev,value.st_ino)
                    self._temporary_paths[temporary]=(value.st_dev,value.st_ino,
                        os.path.realpath(os.path.dirname(temporary)),os.path.realpath(temporary))
                os.chmod(temporary,0o600)
                output=os.fdopen(fd,'wb')
                with self._lock:
                    self._temporary_fds.pop(temporary,None)
                    self._temporary_outputs.append(output)
                with output:
                    download=self.connect()
                    self._download_into(download,request,output,maximum,progress)
                result=self.receiver.receive(temporary,request['taskId'],self.cancelled,progress=file_progress,
                    expected_files=request['fileCount'],expected_bytes=request['totalSize'])
            # Retain local committed bytes immediately, including when the
            # original budget expires before an optional peer completion ACK.
            self.local_commit_result=result
            result['peer_ack_verified']=False
            # Give the sender a bounded opportunity to acknowledge completion.
            # A closed socket or missing ACK never implies a phone UI success.
            try:
                stream.deadline=min(stream.deadline,self._budget.now()+5)
                # Once files are atomically committed, a peer write failure
                # cannot erase that local fact or invite a duplicate retry.
                ws.send(WsMessage('action',2,'status',{'taskId':request['taskId'],'id':request['taskId'],'type':1,'reason':'ok'}))
                ack=ws.receive()
                result['peer_ack_verified']=ack.msg_type=='ack' and ack.id==2 and ack.name=='status'
            except (TransportError,ProtocolError,OSError):pass
            return result
        finally:
            self._life.close_socket(stream.socket)
            if download is not None:self._life.close_socket(download.socket)

    def _download_into(self,download,request,output,maximum,progress):
        self._check()
        download.send(('GET /download?taskId='+request['taskId']+' HTTP/1.1\r\nHost: '+
            self.host+':'+str(self.port)+'\r\nConnection: close\r\n\r\n').encode('ascii'))
        first,headers=read_headers(download)
        if re.match(br'^HTTP/1\.[01] 200(?: |$)',first) is None:
            raise TransportError('Download HTTP status is not 200')
        def space(count):
            self._check()
            self.receiver._space(request['totalSize']+count)
            self._check()
        def advance(count):
            self._check()
            if progress is not None:progress(count)
            self._check()
        download_body(download,headers,output,maximum=maximum,progress=advance,space_check=space)
        self._check();output.flush();self._check();os.fsync(output.fileno());self._check()

    def _bound_pending(self):
        return any(row['closed'] is not True or row['removed'] is not True for row in self._bound_downloads)

    def _cleanup_bound(self):
        for row in self._bound_downloads:
            resource=row['resource']
            if resource is None:continue
            if row['close_attempted'] is not True:
                row['close_attempted']=True
                try:row['closed']=self.directory_binding.close_download(resource) is True
                except BaseException as failure:row['failures'].append(failure)
            if row['closed'] is True and row['remove_attempted'] is not True:
                row['remove_attempted']=True
                try:row['removed']=self.directory_binding.remove_download(resource) is True
                except BaseException as failure:row['failures'].append(failure)
        # No retry of an unknown close or stale numeric FD; retained failures
        # and resource rows stay owned by this original transport.
        return not self._bound_pending()

    def _cleanup_temporary(self,ignore_thread=None):
        if not self._life.actors_quiet(ignore_thread):return False
        with self._lock:
            self._cleanup_bound()
            for output in list(self._temporary_outputs):
                try:
                    output.close()
                    if output.closed is True:self._temporary_outputs.remove(output)
                except Exception:pass
            for path,identity in list(self._temporary_fds.items()):
                fd,device,inode=identity
                try:
                    if device is None or inode is None:continue
                    current=os.fstat(fd)
                    if (current.st_dev,current.st_ino)!=(device,inode):continue
                    os.close(fd)
                    self._temporary_fds.pop(path,None)
                except Exception:pass
            if not self._temporary_outputs and not self._temporary_fds:
                for path,identity in list(self._temporary_paths.items()):
                    try:
                        if identity is None:continue
                        device,inode,parent,canonical=identity
                        current=os.lstat(path)
                        if (not stat.S_ISREG(current.st_mode) or
                            (current.st_dev,current.st_ino)!=(device,inode) or
                            os.path.realpath(os.path.dirname(path))!=parent or os.path.realpath(path)!=canonical):continue
                        os.unlink(path)
                        self._temporary_paths.pop(path,None)
                    except FileNotFoundError:self._temporary_paths.pop(path,None)
                    except Exception:pass
            return not (self._temporary_paths or self._temporary_fds or self._temporary_outputs or self._bound_pending())

    def close(self,timeout=2):
        self._cancelled.set()
        self._life.close(timeout)
        self._cleanup_temporary()
        return self.closed()

    def lifecycle_status(self):
        result=self._life.snapshot()
        with self._lock:
            result['cleanup_pending']=bool(self._temporary_paths or self._temporary_fds or self._temporary_outputs or self._bound_pending())
            result['bound_download_records']=len(self._bound_downloads)
        result['close_verified']=result['close_verified'] and not result['cleanup_pending']
        return result

    def closure_snapshot(self,raw):
        result=self._life.snapshot(raw)
        with self._lock:
            result['cleanup_pending']=bool(self._temporary_paths or self._temporary_fds or self._temporary_outputs or self._bound_pending())
            result['bound_download_records']=len(self._bound_downloads)
        result['close_verified']=result['close_verified'] and not result['cleanup_pending']
        return result

    def closed(self):
        return self.lifecycle_status()['close_verified']
