"""Finite independent Qt UI trial; no original process or radio mutations."""
import argparse
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

import p011_json as json
from mta_safety import AREA,identity,owned_directory,stock_snapshot,require_stock,verify_candidate
from mta_service import State,Server


def write_new(path,text):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        stream.write(text);stream.flush();os.fsync(stream.fileno())


def _file_identity(value):
    return (value.st_dev,value.st_ino,value.st_uid,value.st_mode,value.st_nlink)


def acquire_lock(session,candidate):
    """Fixed private lock; retain exact inode/process ownership for cleanup."""
    path=AREA+'/mta-ui.lock';os.mkdir(path,0o700)
    directory=os.lstat(path);owner=identity(os.getpid())
    values={'session.txt':session+'\n','owner.json':json.dumps({'owner':owner,'candidate':candidate})}
    records={}
    for name,text in values.items():
        write_new(path+'/'+name,text);records[name]=(_file_identity(os.lstat(path+'/'+name)),text.encode('utf-8'))
    return {'path':path,'directory':_file_identity(directory),'owner':owner,'files':records}


def release_lock(record,verified):
    # No file removal at all when any live/unknown actor remains.
    if verified is not True or record is None:return False
    path=AREA+'/mta-ui.lock'
    try:
        if record['path']!=path or identity(os.getpid())!=record['owner']:return False
        if os.path.realpath(path)!=path or _file_identity(os.lstat(path))!=record['directory']:return False
        if not stat.S_ISDIR(record['directory'][3]) or stat.S_IMODE(record['directory'][3])!=0o700:return False
        if set(os.listdir(path))!=set(record['files']):return False
        for name,(expected,contents) in record['files'].items():
            filename=path+'/'+name;value=os.lstat(filename)
            if _file_identity(value)!=expected or not stat.S_ISREG(value.st_mode) or value.st_nlink!=1:return False
            if value.st_uid!=record['directory'][2] or stat.S_IMODE(value.st_mode)!=0o600:return False
            fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                if _file_identity(os.fstat(fd))!=expected or os.read(fd,len(contents)+1)!=contents:return False
            finally:os.close(fd)
        # The directory is private 0700; still recheck every exact object before
        # unlink and never recurse/delete an unexpected member or replacement.
        for name,(expected,contents) in record['files'].items():
            if _file_identity(os.lstat(path))!=record['directory'] or _file_identity(os.lstat(path+'/'+name))!=expected:return False
            os.unlink(path+'/'+name)
        os.rmdir(path);return True
    except (OSError,ValueError,KeyError):return False


def close_http(server,worker):
    """Retain known exact request threads while shutting down this server only."""
    with server.worker_lock:actors=list(server.workers.values())
    for thread in threading.enumerate():
        if getattr(getattr(thread,'_target',None),'__self__',None) is server and not any(item is thread for item in actors):actors.append(thread)
    stopped=True
    try:server.server_close()
    except BaseException:stopped=False
    if worker is not None and not any(item is worker for item in actors):actors.append(worker)
    deadline=time.monotonic()+2
    for thread in actors:
        if thread is not threading.current_thread() and thread.ident is not None:
            thread.join(max(0,deadline-time.monotonic()))
    with server.worker_lock:remaining=list(server.workers.values())
    return (stopped and server.stopping.is_set() is True and server.socket._closed is True and not remaining and
            all(thread.is_alive() is False for thread in actors))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--session',required=True)
    args=parser.parse_args();base=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    source=verify_candidate(base)
    if re.match(r'^'+AREA+r'/sessions/mta-ui-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$',args.session) is None:raise ValueError('Invalid session')
    owned_directory(args.session);before=stock_snapshot();require_stock(before)
    if os.path.lexists(AREA+'/native.lock'):raise ValueError('Another UI trial requires inspection')
    lock_record=acquire_lock(args.session,source)
    result={'evidence_level':'P011_QML_NO_RADIO','candidate_identity':source,'ui_exit':None,
            'original_processes_signalled':False,'radio_actions_allowed':False}
    child=None;server=None;state=None;worker=None;stopping=threading.Event()
    child_spawn_claimed=False;child_spawn_unknown=False;worker_start_unknown=False
    def stop(signum,frame):stopping.set()
    for name in ('SIGTERM','SIGINT','SIGALRM'):signal.signal(getattr(signal,name),stop)
    signal.alarm(60)
    try:
        write_new(args.session+'/owner.json',json.dumps(identity(os.getpid())))
        userroot=owned_directory(args.session+'/test-user',True)
        owned_directory(userroot+'/Text',True)
        write_new(userroot+'/Text/P011-UI-TEST-NOT-USER.txt','P011 UI FIXTURE!')
        state=State(userroot,base+'/native/mta-bluez-helper',base+'/native/mta-network-helper')
        server=Server(state,bootstrap=True)
        worker=threading.Thread(target=server.serve_forever);worker.daemon=True
        try:worker.start()
        except BaseException:worker_start_unknown=True;raise
        with open(base+'/runtime/MtaTrial.qml',encoding='utf-8') as f:template=f.read()
        for key,value in {'DEVICE_URL':'file://'+base+'/device','CAPTURE_DIR':args.session,'ENDPOINT':'http://'+server.expected_host}.items():
            template=template.replace('@@'+key+'@@',value)
        if '@@' in template:raise ValueError('Incomplete QML template')
        path=args.session+'/tst_mta.qml';write_new(path,template)
        env=dict(os.environ);env.update({'XDG_RUNTIME_DIR':'/run/user/0','WAYLAND_DISPLAY':'wayland-0',
                'QT_QPA_PLATFORM':'wayland','QT_QUICK_BACKEND':'software','QSG_RENDER_LOOP':'basic',
                'QML_DISABLE_DISK_CACHE':'1','PYTHONDONTWRITEBYTECODE':'1'})
        with open(args.session+'/ui.stdout.raw','xb') as stdout,open(args.session+'/ui.stderr.raw','xb') as stderr:
            child_spawn_claimed=True
            try:
                child=subprocess.Popen([sys.executable,'-B',base+'/runtime/qt_quicktest_runner.py','--input',path],
                                       stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)
            except BaseException:child_spawn_unknown=True;raise
            deadline=time.monotonic()+35
            while child.poll() is None and time.monotonic()<deadline and not stopping.wait(.2):
                if os.path.isfile(args.session+'/STOP'):break
            if child.poll() is None:
                child.terminate()
                try:child.wait(4)
                except subprocess.TimeoutExpired:child.kill();child.wait(3)
            result['ui_exit']=child.returncode
            result['no_radio_actions']=state.helper is None and not state.event_counts
    except Exception:
        result['error']='SESSION_FAILED_SEE_PRIVATE_LOGS'
        import traceback;traceback.print_exc()
    finally:
        try:
            if child is not None and child.poll() is None:
                child.terminate()
                try:child.wait(3)
                except subprocess.TimeoutExpired:child.kill();child.wait(3)
            result['ui_closed']=not child_spawn_unknown and ((child is None and not child_spawn_claimed) or (child is not None and child.poll() is not None))
        except BaseException:result['ui_closed']=False
        if server:
            try:
                address=server.server_address
                result['http_requests_closed']=close_http(server,worker) and not worker_start_unknown
                probe=socket.socket();probe.settimeout(.5)
                try:result['loopback_closed']=probe.connect_ex(address)!=0
                finally:probe.close()
                result['http_worker_closed']=not worker_start_unknown and worker is not None and worker.is_alive() is False
            except BaseException:result['http_requests_closed']=False;result['loopback_closed']=False;result['http_worker_closed']=False
        try:result['resources_closed']=state is not None and state.close() is True and state.closed() is True
        except BaseException:result['resources_closed']=False
        after=stock_snapshot()
        result['stock_hashes_unchanged']=before['hashes']==after['hashes']
        result['stock_processes_unchanged']=before['processes']==after['processes']
        result['pass']=result['ui_exit']==0 and 'error' not in result and all(result.get(k,False) for k in
                   ['no_radio_actions','ui_closed','loopback_closed','http_worker_closed','http_requests_closed','resources_closed','stock_hashes_unchanged','stock_processes_unchanged'])
        cleanup=all(result.get(k) is True for k in ('ui_closed','loopback_closed','http_worker_closed','http_requests_closed','resources_closed',
                                                   'stock_hashes_unchanged','stock_processes_unchanged'))
        result['occupancy_released']=release_lock(lock_record,cleanup)
        result['cleanup_pending']=not result['occupancy_released']
        result['pass']=result['pass'] and result['occupancy_released']
        write_new(args.session+'/result.json',json.dumps(result,indent=2))
        signal.alarm(0)
    print('RESULT='+repr(result));return 0 if result['pass'] else 1


if __name__=='__main__':sys.exit(main())
