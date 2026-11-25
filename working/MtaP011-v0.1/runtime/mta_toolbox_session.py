"""Finite copied-toolbox/MTA UI test. No stock/radio mutations or user files."""
import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

import p011_json as json
from mta_safety import AREA,identity,owned_directory,stock_snapshot,require_stock,verify_candidate
from mta_ui_session import write_new,acquire_lock,release_lock,close_http
from mta_service import State as MtaState,Server as MtaServer


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--session',required=True)
    args=parser.parse_args();base=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    source=verify_candidate(base)
    if re.match(r'^'+AREA+r'/sessions/mta-toolbox-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$',args.session) is None:
        raise ValueError('Invalid session')
    owned_directory(args.session);before=stock_snapshot();require_stock(before)
    if any(os.path.lexists(AREA+'/'+name) for name in ('native.lock','mta-ui.lock')):
        raise ValueError('Another UI trial requires inspection')
    copied=base+'/integration/ToolboxMta-v0.1'
    sys.path.insert(0,copied+'/runtime')
    from mta_toolbox_server import State as ToolboxState,BoundedServer
    lock_record=acquire_lock(args.session,source)
    result={'evidence_level':'P011_TOOLBOX_QML_NO_RADIO','candidate_identity':source,
            'original_processes_signalled':False,'radio_actions_allowed':False,'ui_exit':None}
    child=None;mta=None;toolbox=None;servers=[];stopping=threading.Event()
    child_spawn_claimed=False;child_spawn_unknown=False;worker_start_unknown=False
    def stop(signum,frame):stopping.set()
    for name in ('SIGTERM','SIGINT','SIGALRM'):signal.signal(getattr(signal,name),stop)
    signal.alarm(80)
    try:
        write_new(args.session+'/owner.json',json.dumps(identity(os.getpid())))
        userroot=owned_directory(args.session+'/test-user',True)
        toolbox=ToolboxState(userroot,flat_web_root=copied+'/web')
        write_new(userroot+'/Text/P011-UI-TEST-NOT-USER.txt','P011 UI FIXTURE!')
        write_new(userroot+'/Received/P011-UI-RECEIVED-NOT-PHONE.txt','P011 UI FIXTURE!')
        mta=MtaState(userroot,base+'/native/mta-bluez-helper',base+'/native/mta-network-helper')
        old=BoundedServer(('127.0.0.1',0),toolbox);servers.append((old,None))
        new=MtaServer(mta);servers.append((new,None))
        for index,(server,unused) in enumerate(servers):
            worker=threading.Thread(target=server.serve_forever);worker.daemon=True
            servers[index]=(server,worker)
            try:worker.start()
            except BaseException:worker_start_unknown=True;raise
        with open(base+'/runtime/MtaToolboxTrial.qml',encoding='utf-8') as handle:template=handle.read()
        values={'TOOLBOX_URL':'file://'+copied+'/device','CAPTURE_DIR':args.session,
                'TOOLBOX_ENDPOINT':'http://'+old.expected_host,'TOOLBOX_TOKEN':toolbox.token,
                'MTA_ENDPOINT':'http://'+new.expected_host,'MTA_TOKEN':mta.token}
        for key,value in values.items():template=template.replace('@@'+key+'@@',value)
        if '@@' in template:raise ValueError('Incomplete QML template')
        path=args.session+'/tst_toolbox.qml';write_new(path,template)
        env=dict(os.environ);env.update({'XDG_RUNTIME_DIR':'/run/user/0','WAYLAND_DISPLAY':'wayland-0',
                'QT_QPA_PLATFORM':'wayland','QT_QUICK_BACKEND':'software','QSG_RENDER_LOOP':'basic',
                'QML_DISABLE_DISK_CACHE':'1','PYTHONDONTWRITEBYTECODE':'1'})
        with open(args.session+'/ui.stdout.raw','xb') as stdout,open(args.session+'/ui.stderr.raw','xb') as stderr:
            child_spawn_claimed=True
            try:
                child=subprocess.Popen([sys.executable,'-B',base+'/runtime/qt_quicktest_runner.py','--input',path],
                                       stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env)
            except BaseException:child_spawn_unknown=True;raise
            deadline=time.monotonic()+50
            while child.poll() is None and time.monotonic()<deadline and not stopping.wait(.2):
                if os.path.isfile(args.session+'/STOP'):break
            if child.poll() is None:
                child.terminate()
                try:child.wait(4)
                except subprocess.TimeoutExpired:child.kill();child.wait(3)
            result['ui_exit']=child.returncode
            result['no_radio_actions']=mta.helper is None and not mta.event_counts and toolbox.lan is None
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
        closed=[]
        for server,worker in servers:
            try:
                address=server.server_address;actors_closed=close_http(server,worker)
                probe=socket.socket();probe.settimeout(.5)
                try:closed.append(probe.connect_ex(address)!=0 and actors_closed)
                finally:probe.close()
            except BaseException:closed.append(False)
        result['loopbacks_closed']=len(closed)==2 and all(closed) and not worker_start_unknown
        try:result['mta_resources_closed']=mta is not None and mta.close() is True and mta.closed() is True
        except BaseException:result['mta_resources_closed']=False
        try:
            if toolbox:toolbox.close()
            result['toolbox_resources_closed']=bool(toolbox and not toolbox.worker.is_alive() and toolbox.lan is None)
        except BaseException:result['toolbox_resources_closed']=False
        after=stock_snapshot()
        result['stock_hashes_unchanged']=before['hashes']==after['hashes']
        result['stock_processes_unchanged']=before['processes']==after['processes']
        result['pass']=result['ui_exit']==0 and 'error' not in result and all(result.get(k,False) for k in
                ['no_radio_actions','ui_closed','loopbacks_closed','mta_resources_closed','toolbox_resources_closed',
                 'stock_hashes_unchanged','stock_processes_unchanged'])
        cleanup=all(result.get(k) is True for k in ('ui_closed','loopbacks_closed','mta_resources_closed',
                                                   'toolbox_resources_closed','stock_hashes_unchanged','stock_processes_unchanged'))
        result['occupancy_released']=release_lock(lock_record,cleanup)
        result['cleanup_pending']=not result['occupancy_released']
        result['pass']=result['pass'] and result['occupancy_released']
        write_new(args.session+'/result.json',json.dumps(result,indent=2))
        signal.alarm(0)
    print('RESULT='+repr(result));return 0 if result['pass'] else 1


if __name__=='__main__':sys.exit(main())
