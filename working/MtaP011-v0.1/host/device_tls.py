"""Finite P011 TLS/WSS loopback evidence with synthetic files only.

This deliberately imports no radio, Wi-Fi, native helper, service or QML code.
An explicit in-process loopback fixture is not a production permission change.
Raw output and the immutable source snapshot remain private and are never put
in the sanitized ZIP. A failed test never restarts or repairs the device.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zipfile

from device_probe import Adb, BASE, ROOT


SOURCE_NAMES = (
    "p011_json.py", "mta_safety.py", "mta_protocol.py", "mta_files.py",
    "mta_storage.py", "mta_transport.py", "mta_sender.py",
)
PUBLIC_REMOTE_KEYS = frozenset((
    "evidence_level", "pass", "radio_operations", "ui_started", "phone_interop",
    "production_wifi_sender", "user_files_accessed", "python_version", "ssl_version",
    "loopback_fixture", "request_verified", "actual_bytes_verified",
    "receiver_peer_ack_verified", "sender_peer_completion_verified",
    "owned_cleanup_verified", "certificates_removed", "selection_closed",
    "receiver_temporary_removed", "synthetic_file_count", "synthetic_total_bytes",
    "synthetic_sha256", "openssl_cli_version", "archive_bytes_received",
    "archive_bytes_sent", "tls_versions", "state_sequence", "final_file_progress",
    "elapsed_seconds", "error_stage", "error_class",
    "initial_peer_denied", "denied_peer_no_worker_or_claim", "peer_authorized_once",
    "receiver_source_socket_fixture_verified", "scoped_socket_factory_calls",
    "sender_bound_listener_fixture_verified", "scoped_listener_factory_calls",
    "sender_transport_closed", "receiver_transport_closed",
    "sender_closure_proof_verified", "receiver_closure_proofs_verified",
    "sender_lifecycle", "receiver_lifecycle",
))


def snapshot(destination):
    """Freeze only TLS dependencies, without a concurrently edited helper."""
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "runtime").mkdir()
    lines = []
    for name in sorted(SOURCE_NAMES):
        data = (BASE / "runtime" / name).read_bytes()
        # Check the exact snapshot, not later mutable working-tree contents.
        ast.parse(data.decode("utf-8"), filename=name, feature_version=(3, 5))
        (destination / "runtime" / name).write_bytes(data)
        lines.append("%s %d runtime/%s\n" % (hashlib.sha256(data).hexdigest(), len(data), name))
    manifest = "".join(lines).encode("ascii")
    (destination / "SOURCE.sha256").write_bytes(manifest)
    return hashlib.sha256(manifest).hexdigest()[:16]


def permissions_source(target, staging):
    """Exact new TLS snapshot only; verify ALL eight FDs before any fchmod.

    This is explicit project-candidate setup, not a read-only device check. No
    imports from that candidate occur here; old candidates are never targeted.
    """
    staging = Path(staging)
    candidate = hashlib.sha256((staging / 'SOURCE.sha256').read_bytes()).hexdigest()[:16]
    if target != '/mnt/data/p011-toolbox/candidates/mta-01-' + candidate:
        raise ValueError('TLS setup target does not match exact snapshot')
    names = ('SOURCE.sha256',) + tuple('runtime/' + name for name in sorted(SOURCE_NAMES))
    expected = tuple((name, len((staging / name).read_bytes()),
                      hashlib.sha256((staging / name).read_bytes()).hexdigest()) for name in names)
    body = r'''
import hashlib,os,stat,sys,time
if sys.flags.optimize or os.geteuid()!=0:raise ValueError('TLS setup interpreter or owner')
end=time.monotonic()+20;files=[];changed=0
def budget():
 if time.monotonic()>=end:raise ValueError('TLS setup deadline')
def meta(row):
 return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
def path_identity(path,fd):
 budget();a=os.lstat(path);b=os.fstat(fd)
 if meta(a)!=meta(b):raise ValueError('TLS setup identity changed')
 return b
def digest_fd(fd,size):
 os.lseek(fd,0,0);h=hashlib.sha256();left=size
 while left:
  budget();block=os.read(fd,min(left,65536))
  if not block:raise ValueError('TLS setup short read')
  h.update(block);left-=len(block)
 if os.read(fd,1):raise ValueError('TLS setup extra bytes')
 return h.hexdigest()
try:
 if TARGET!=AREA+'/candidates/mta-01-'+CANDIDATE:raise ValueError('TLS setup candidate target')
 if not os.path.isabs(TARGET) or os.path.realpath(TARGET)!=TARGET:raise ValueError('TLS setup redirected directory')
 for path in (AREA,AREA+'/candidates',TARGET,TARGET+'/runtime'):
  row=os.lstat(path)
  if not stat.S_ISDIR(row.st_mode) or row.st_uid!=os.geteuid() or row.st_mode&0o7777!=0o700:
   raise ValueError('TLS setup private directory')
 if set(os.listdir(TARGET))!={'SOURCE.sha256','runtime'} or set(os.listdir(TARGET+'/runtime'))!=set(x[0][8:] for x in EXPECTED[1:]):
  raise ValueError('TLS setup file set')
 for name,size,pin in EXPECTED:
  budget();path=TARGET+'/'+name
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);files.append((fd,path,size,pin,None))
  row=path_identity(path,fd)
  if not stat.S_ISREG(row.st_mode) or row.st_uid!=os.geteuid() or row.st_nlink!=1 or row.st_size!=size or row.st_mode&0o7777 not in (0o666,0o400):
   raise ValueError('TLS setup file metadata')
  if digest_fd(fd,size)!=pin or meta(path_identity(path,fd))!=meta(row):raise ValueError('TLS setup file pin')
  files[-1]=(fd,path,size,pin,meta(row))
 for fd,path,size,pin,before in files:
  row=path_identity(path,fd)
  if meta(row)!=before:raise ValueError('TLS setup changed before write')
  if row.st_mode&0o7777!=0o400:os.fchmod(fd,0o400);changed+=1
  final=path_identity(path,fd);after=meta(final)
  if final.st_mode&0o7777!=0o400 or (after[:2]+after[3:8])!=(before[:2]+before[3:8]) or digest_fd(fd,size)!=pin or meta(path_identity(path,fd))!=after:
   raise ValueError('TLS setup readback')
finally:
 failed=False
 for fd,path,size,pin,before in files:
  try:os.close(fd)
  except OSError:failed=True
 if failed:raise ValueError('TLS setup descriptor close')
print('RESULT='+repr({'complete':True,'file_count':len(files),'permission_writes':changed,'descriptors_closed':True}))
'''
    value = 'AREA="/mnt/data/p011-toolbox"\nTARGET=' + repr(target) + '\nCANDIDATE=' + repr(candidate) + '\nEXPECTED=' + repr(expected) + '\n' + body
    ast.parse(value, feature_version=(3, 5))
    return value


DEVICE_BODY = r'''
import hashlib,os,socket,ssl,subprocess,sys,time
from mta_safety import owned_directory,verify_candidate

def check(condition):
 if not condition:raise AssertionError('synthetic TLS invariant failed')

def digest_file(path):
 value=hashlib.sha256()
 with open(path,'rb') as handle:
  for block in iter(lambda:handle.read(65536),b''):value.update(block)
 return value.hexdigest()

def write_new(path,value):
 descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(descriptor,'wb') as handle:
  handle.write(value);handle.flush();os.fsync(handle.fileno())

result={'evidence_level':'P011_TLS_LOOPBACK_SYNTHETIC','pass':False,
 'radio_operations':False,'ui_started':False,'phone_interop':'NOT_TESTED',
 'production_wifi_sender':'NOT_TESTED','user_files_accessed':False,
 'python_version':tuple(sys.version_info[:3]),'ssl_version':ssl.OPENSSL_VERSION,
 'loopback_fixture':True,'request_verified':False,'actual_bytes_verified':False,
 'receiver_peer_ack_verified':False,'sender_peer_completion_verified':False,
 'owned_cleanup_verified':False,'certificates_removed':False,
 'selection_closed':False,'receiver_temporary_removed':False,
 'initial_peer_denied':False,'denied_peer_no_worker_or_claim':False,'peer_authorized_once':False,
 'receiver_source_socket_fixture_verified':False,'scoped_socket_factory_calls':0,
 'sender_bound_listener_fixture_verified':False,'scoped_listener_factory_calls':0,
 'sender_transport_closed':False,'receiver_transport_closed':False,
 'sender_closure_proof_verified':False,'receiver_closure_proofs_verified':False}
server=None;receiver=None;selection=None;process=None;old_private=None;patch_active=False
stage='candidate';started=time.monotonic()
try:
 check(verify_candidate(TARGET)[:16]==CANDIDATE)
 owned_directory(SESSION)
 for suffix in ('user','user/Music','user/Text','Received','private'):
  owned_directory(SESSION+'/'+suffix,True)
 stage='synthetic_sources'
 payloads={'Music/synthetic.bin':bytes(bytearray(range(256)))*4097,
           'Text/synthetic.txt':('P011 TLS/WSS synthetic only\n互传回环，不涉及用户文件。\n'*31).encode('utf-8')}
 expected={}
 for name,data in payloads.items():
  write_new(SESSION+'/user/'+name,data)
  expected[name]=(len(data),hashlib.sha256(data).hexdigest())
 total=sum(row[0] for row in expected.values())
 result['synthetic_file_count']=len(expected);result['synthetic_total_bytes']=total
 result['synthetic_sha256']=sorted(row[1] for row in expected.values())
 stage='imports'
 from mta_files import FileRegistry
 from mta_storage import SafeZipReceiver
 from mta_sender import SenderError,SenderTransport
 import mta_transport
 from mta_transport import ReceiverTransport
 stage='openssl_version'
 process=subprocess.Popen(['/usr/bin/openssl','version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 output,error=process.communicate(timeout=3)
 check(process.returncode==0)
 result['openssl_cli_version']=output.decode('ascii','replace').strip()
 process=None
 stage='selection'
 registry=FileRegistry(SESSION+'/user')
 rows=registry.list_files();check(len(rows)==len(expected))
 selection=registry.open_selection([row['id'] for row in rows])
 check(selection.total_bytes==total)
 # The MTA sender intentionally namespaces ZIP members by selection index.
 # Verify this exact mapping; do not discard unexpected directory prefixes.
 archive_expected={str(index)+'/'+entry['name']:expected[entry['name']]
   for index,entry in enumerate(selection.entries)}
 storage=SafeZipReceiver(SESSION+'/Received')
 events=[]
 def state_callback(state,details):
  # No names/credentials/certificate data are retained, even privately.
  if not events or events[-1]!=state:events.append(state)
 stage='sender_start'
 listeners=[]
 def listener_fixture(host,port):
  raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  try:
   raw.bind((host,port));listeners.append((raw,raw.getsockname()));return raw
  except Exception:
   raw.close();raise
 server=SenderTransport('127.0.0.1',0,selection,'/usr/bin/openssl',
   sender_name='Synthetic P011',sender_id='0011',task_id='p011-tls-synthetic',
   timeout=30,allow_loopback=True,
   state_callback=state_callback,temp_root=SESSION+'/private',listener_factory=listener_fixture)
 server.start()
 check(len(listeners)==1 and listeners[0][1]==('127.0.0.1',server.port))
 result['sender_bound_listener_fixture_verified']=True;result['scoped_listener_factory_calls']=len(listeners)
 stage='actual_initial_deny'
 check(server.allowed_peer_ip is None)
 with socket.create_connection(('127.0.0.1',server.port),2) as denied:
  denied.settimeout(2);check(denied.recv(1)==b'')
 result['initial_peer_denied']=True
 check(not server._workers and server._peer_ip is None and not server._ws_claimed and server.result is None)
 result['denied_peer_no_worker_or_claim']=True
 stage='actual_one_time_authorization'
 check(server.authorize_peer('127.0.0.1') is True)
 check(server.authorize_peer('127.0.0.1') is True)
 replaced=False
 try:server.authorize_peer('192.168.49.2');replaced=True
 except SenderError:pass
 check(not replaced and server.allowed_peer_ip=='127.0.0.1')
 result['peer_authorized_once']=True
 stage='receiver_constructor'
 old_private=mta_transport.private_ipv4
 def test_private(value):
  if value=='127.0.0.1':return value
  return old_private(value)
 mta_transport.private_ipv4=test_private;patch_active=True
 scoped=[]
 def scoped_fixture(host,port,timeout):
  raw=socket.create_connection((host,port),timeout,source_address=('127.0.0.1',0))
  scoped.append((raw,raw.getsockname()[0],raw.getpeername()))
  return raw
 try:receiver=ReceiverTransport('127.0.0.1',server.port,storage,timeout=30,
   socket_factory=scoped_fixture,source_ip='127.0.0.1')
 finally:mta_transport.private_ipv4=old_private;patch_active=False
 versions=[];network=[];files=[];requests=[]
 original_connect=receiver.connect
 def observed_connect():
  stream=original_connect();versions.append(stream.socket.version());return stream
 receiver.connect=observed_connect
 def confirm(request):
  requests.append((request['taskId'],request['fileCount'],request['totalSize']))
  ok=request['taskId']==server.task_id and request['fileCount']==len(expected) and request['totalSize']==total
  check(ok);result['request_verified']=True;return True
 stage='actual_tls_receive'
 received=receiver.run(confirm,progress=network.append,
   file_progress=lambda done,size:files.append((done,size)))
 result['receiver_peer_ack_verified']=received.get('peer_ack_verified') is True
 stage='actual_sender_completion'
 sent=server.wait()
 result['sender_peer_completion_verified']=sent.get('peer_completion_verified') is True
 result['archive_bytes_received']=network[-1] if network else 0
 result['archive_bytes_sent']=sent.get('archiveBytesSent',0)
 result['tls_versions']=versions
 result['state_sequence']=events
 stage='request_and_tls_counts'
 check(len(requests)==1 and len(versions)==2 and all(version=='TLSv1.2' for version in versions))
 stage='scoped_source_fixture'
 check(len(scoped)==2 and all(row[1]=='127.0.0.1' and row[2]==('127.0.0.1',server.port) for row in scoped))
 result['receiver_source_socket_fixture_verified']=True;result['scoped_socket_factory_calls']=len(scoped)
 stage='receiver_manifest_counts'
 check(received['fileCount']==len(expected) and received['totalSize']==total)
 stage='sender_manifest_counts'
 check(sent['fileCount']==len(expected) and sent['totalSize']==total)
 stage='completion_ack'
 check(result['receiver_peer_ack_verified'] and result['sender_peer_completion_verified'])
 stage='progress_totals'
 result['final_file_progress']=files[-1] if files else None
 check(network and network[-1]==sent['archiveBytesSent'] and files[-1]==(total,total))
 observed={}
 stage='saved_path_identity'
 for path in received['files']:
  relative=os.path.relpath(path,received['directory'])
  check(relative in archive_expected and relative not in observed)
  observed[relative]=(os.path.getsize(path),digest_file(path))
 stage='saved_byte_hashes'
 check(observed==archive_expected)
 result['actual_bytes_verified']=True
 stage='complete'
 result['pass']=True
except Exception as error:
 result['error_stage']=stage;result['error_class']=type(error).__name__
finally:
 cleanup_ok=True
 if patch_active:
  mta_transport.private_ipv4=old_private
 if process is not None:
  try:
   if process.poll() is None:process.kill()
   process.communicate(timeout=3)
  except Exception:cleanup_ok=False
 def closure_ok(value):
  return (type(value) is dict and value.get('recognized_raw') is True and
   value.get('all_sockets_closed') is True and value.get('all_actors_exited') is True and
   value.get('close_verified') is True and value.get('cleanup_pending') is False)
 def public_lifecycle(owner):
  value=owner.lifecycle_status()
  names=('closing','socket_records','sockets_pending','actors_pending','threads_pending',
   'wrappers_pending','unknown_wrappers','unknown_resources','processes_pending','close_verified','cleanup_pending')
  return {name:value[name] for name in names if name in value}
 if receiver is not None:
  try:
   result['receiver_transport_closed']=receiver.close(timeout=2) is True and receiver.closed() is True
   result['receiver_lifecycle']=public_lifecycle(receiver)
   result['receiver_closure_proofs_verified']=len(scoped)==2 and all(closure_ok(receiver.closure_snapshot(row[0])) for row in scoped)
  except Exception:cleanup_ok=False
  cleanup_ok=cleanup_ok and result['receiver_transport_closed'] and result['receiver_closure_proofs_verified']
 if server is not None:
  try:
   result['sender_transport_closed']=server.close(timeout=2) is True and server.closed() is True
   result['sender_lifecycle']=public_lifecycle(server)
   result['sender_closure_proof_verified']=len(listeners)==1 and closure_ok(server.closure_snapshot(listeners[0][0]))
  except Exception:cleanup_ok=False
  cleanup_ok=cleanup_ok and result['sender_transport_closed'] and result['sender_closure_proof_verified']
  threads=list(server._workers)
  if server._listener_thread is not None:threads.append(server._listener_thread)
  cleanup_ok=cleanup_ok and not any(thread.is_alive() for thread in threads)
  cleanup_ok=cleanup_ok and (server._listener is None or server._listener.fileno()==-1)
  cleanup_ok=cleanup_ok and all(row[0].fileno()==-1 for row in listeners)
 if selection is not None:
  try:selection.close()
  except Exception:cleanup_ok=False
  result['selection_closed']=selection.closed
 else:result['selection_closed']=True
 private=SESSION+'/private';incoming=SESSION+'/Received'
 result['certificates_removed']=os.path.isdir(private) and not os.listdir(private)
 result['receiver_temporary_removed']=os.path.isdir(incoming) and not any(name.startswith('.mta-') for name in os.listdir(incoming))
 result['owned_cleanup_verified']=cleanup_ok and result['selection_closed'] and result['certificates_removed'] and result['receiver_temporary_removed']
 result['elapsed_seconds']=round(time.monotonic()-started,3)
 result['pass']=result['pass'] and result['owned_cleanup_verified']
print('RESULT='+repr(result))
'''


def source(target, session, identity):
    prefix = "import sys\nsys.path.insert(0," + repr(target + "/runtime") + ")\n"
    prefix += "TARGET=" + repr(target) + "\nSESSION=" + repr(session) + "\nCANDIDATE=" + repr(identity) + "\n"
    value = prefix + DEVICE_BODY
    ast.parse(value, feature_version=(3, 5))
    return value


def run_trial(output=None):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = secrets.token_hex(4)
    out = Path(output) if output else ROOT / "logs" / ("MtaP011-DeviceTls-" + stamp + "-" + suffix)
    out.mkdir(parents=True, exist_ok=False)
    staging = out / "private-candidate"
    identity = snapshot(staging)
    safety = (staging / "runtime/mta_safety.py").read_text(encoding="utf-8")
    gate = safety + "\ns=stock_snapshot();require_stock(s);print('RESULT='+repr(s))"
    target = "/mnt/data/p011-toolbox/candidates/mta-01-" + identity
    session = "/mnt/data/p011-toolbox/sessions/mta-tls-" + stamp + "-" + suffix
    report = {"evidence_level": "P011_TLS_LOOPBACK_SYNTHETIC", "pass": False,
              "candidate_identity": identity, "radio_operations": False, "ui_started": False,
              "user_files_accessed": False, "phone_interop": "NOT_TESTED",
              "production_wifi_sender": "NOT_TESTED", "stock_identity_unchanged": False}
    before = None
    after = None
    adb = None
    try:
        # Adb internally uses select_target(), never an implicit/default target.
        adb = Adb(out / "private-raw")
        before = adb.python("before-independent", gate)
        create = safety + "\np=" + repr(target) + "\nowned_directory(p,True)\n"
        create += "print('RESULT='+repr({'present':bool(os.listdir(p))}))"
        current = adb.python("candidate-directory", create)
        if not current["present"]:
            adb.python("candidate-subdir", safety + "\nowned_directory(" + repr(target + "/runtime") + ",True)\nprint('RESULT=True')")
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    adb.run("push-candidate", ["push", str(path), target + "/" + path.relative_to(staging).as_posix()])
        # An existing candidate is never replaced. Any partial/different one fails.
        # Verify every exact FD before private imports, then tighten only these
        # new TLS snapshot files. A setup failure does not retry or start TLS.
        report['candidate_permission_setup_requested'] = True
        setup = adb.python('exact-tls-candidate-permissions', permissions_source(target, staging), timeout=40)
        if (type(setup) is not dict or set(setup) != {'complete', 'file_count', 'permission_writes', 'descriptors_closed'} or
                setup['complete'] is not True or setup['descriptors_closed'] is not True or
                type(setup['file_count']) is not int or setup['file_count'] != 8 or
                type(setup['permission_writes']) is not int or not 0 <= setup['permission_writes'] <= 8):
            raise ValueError('TLS snapshot permissions gate')
        report['candidate_permission_setup_complete'] = True
        report['candidate_permission_writes'] = setup['permission_writes']
        check_source = safety + "\nverify_candidate(" + repr(target) + ")\n"
        check_source += "p=" + repr(session) + "\nassert not os.path.lexists(p)\nowned_directory(p,True)\nprint('RESULT=True')"
        adb.python("verify-candidate-session", check_source)
        measured = adb.python("finite-synthetic-tls", source(target, session, identity), timeout=70)
        if not isinstance(measured, dict):
            raise ValueError("Invalid remote report")
        if set(measured) - PUBLIC_REMOTE_KEYS:
            raise ValueError("Unexpected public result field")
        report.update({name: measured[name] for name in PUBLIC_REMOTE_KEYS if name in measured})
    except Exception as error:
        # Never expose raw exception strings (ADB paths/identifiers/peer data).
        report["host_error_class"] = type(error).__name__
        report["pass"] = False
    finally:
        if adb is not None:
            try:
                after = adb.python("after-independent", gate)
            except Exception as error:
                report["after_check_error_class"] = type(error).__name__
        report["stock_identity_unchanged"] = before is not None and after is not None and before == after
        report["independent_stock_gates_passed"] = before is not None and after is not None
        report["pass"] = report["pass"] and report["stock_identity_unchanged"]
    (out / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "README.txt").write_text(
        "P011 合成文件 TLS/WSS 回环证据；实际字节/SHA-256、请求和完成 ACK 分别校验。\n"
        "不启动 RF、Wi-Fi 切换、UI 或原厂替换，不读取用户文件；失败不重启/修系统。\n"
        "loopback 仅是此进程测试 fixture，不代表生产地址策略改变。\n"
        "新增实际准入专项：监听初始 deny-all，拒绝 TCP 不启动 TLS/WS；一次性授权后才传输。\n"
        "接收连接工厂在回环绑定源地址并读回两次端点；不代表SO_BINDTODEVICE/P2P接口绑定通过。\n"
        "发送监听工厂在回环绑定实际端口；关闭后独立保存的原socket读回为已关闭。\n"
        "本轮新增发送/接收transport关闭证明，精确raw→TLS及所有actual actors/threads/temp均须闭合。\n"
        "启动前完整FD核验本次8个TLS候选文件，再仅规范0400；不是只读检查，不修改旧候选或原厂。\n"
        "手机兼容、发送端 P2P/AP、无线恢复与物理输出均未由本轮验收。\n"
        "私有 raw、源候选以及任何证书/私钥不进入 ZIP。仅白名单 result.json/README.txt。\n",
        encoding="utf-8")
    archive = out.with_suffix(".sanitized.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json", "README.txt"):
            bundle.write(out / name, name)
    return report, out, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report, out, archive = run_trial(args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("RESULT_DIR=" + str(out))
    print("RESULT_ZIP=" + str(archive))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
