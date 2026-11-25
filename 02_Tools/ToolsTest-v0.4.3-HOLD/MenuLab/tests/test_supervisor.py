#!/usr/bin/env python3
"""Host-only Linux process tests. Uses fake executables in TemporaryDirectory.
No real /usr/bin/Z03, /mnt/data/p011-menu or device is used. Root is needed only
because the real preflight has a root-ADB check; the test policy points to /tmp.
"""
import os, sys, time, tempfile, pathlib, subprocess, socket, signal, hashlib, shutil, json, importlib.util
PACKAGE = pathlib.Path(__file__).resolve().parents[1]
CASES = sys.argv[1:] or ['normal','crash','stop','worker-killed','guardian-killed','busy-original','candidate-stubborn','preexisting-path','bad-parent']
C = r'''
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
void *keepalive(void *p) { for(;;) usleep(100000); return NULL; }
#ifndef BEHAVIOR
#define BEHAVIOR 0
#endif
int main(int argc,char**argv) {
 setbuf(stdout,NULL);
 printf("Fake app behavior=%d\\n",BEHAVIOR);
 if(BEHAVIOR==1) { usleep(400000); return 23; }
 if(BEHAVIOR==2) signal(SIGTERM,SIG_IGN);
 if(BEHAVIOR==3) { pthread_t th; pthread_create(&th,NULL,keepalive,NULL); pthread_exit(NULL); }
 for(;;) usleep(100000);
}
'''

def waituntil(fn, seconds=8):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        v=fn()
        if v:return v
        time.sleep(.04)
    raise AssertionError('condition timeout')

def filetext(p):
    try:return p.read_text()
    except FileNotFoundError:return ''

summaries=[]
for case in CASES:
    with tempfile.TemporaryDirectory(prefix='p011-guard-test-') as t:
        root=pathlib.Path(t); run=root/'session';run.mkdir();pages=run/'pages';pages.mkdir()
        for f in (PACKAGE/'runtime').glob('*.py'):shutil.copy2(str(f),str(run/f.name))
        (root/'fake.c').write_text(C)
        stock=root/'stock-Z03';cand=run/'Z03'; launcher=root/'zyb_z03_launch.sh'
        for path,beh in [(stock,2 if case=='busy-original' else 0),(cand,1 if case=='crash' else (2 if case=='candidate-stubborn' else (3 if case=='leader-exited' else 0)))]:
            subprocess.check_call(['gcc','-pthread','-O1','-DBEHAVIOR=%d'%beh,str(root/'fake.c'),'-o',str(path)])
        launcher.write_text('#!/bin/sh\nwhile :; do "'+str(stock)+'" -platform wayland &\np=$!\nwait "$p"\ndone\n')
        launcher.chmod(0o700)
        pagehash={}
        for f in (PACKAGE/'examples/device').iterdir():
            if f.suffix not in ('.qml','.js'): continue
            shutil.copy2(str(f),str(pages/f.name));pagehash[f.name]=hashlib.sha256(f.read_bytes()).hexdigest()
        policy={'STOCK':str(stock),'LAUNCHER':str(launcher),'ORIGINAL_SHA256':hashlib.sha256(stock.read_bytes()).hexdigest(),
                'CANDIDATE_SHA256':hashlib.sha256(cand.read_bytes()).hexdigest(),'LAUNCHER_SHA256':hashlib.sha256(launcher.read_bytes()).hexdigest(),
                'MENU_LINK':str(root/'menu-alias'),'LOCK':str(root/'trial-lock'),'FIRMWARE':'host-test','PAGE_HASHES':pagehash}
        (run/'menu_policy.py').write_text(''.join('%s = %r\n'%(k,v) for k,v in policy.items()))
        xdg=root/'runtime';xdg.mkdir();sk=socket.socket(socket.AF_UNIX);sk.bind(str(xdg/'wayland-0'))
        env=os.environ.copy();env['XDG_RUNTIME_DIR']=str(xdg);env['WAYLAND_DISPLAY']='wayland-0'
        lp=subprocess.Popen(['/bin/sh',str(launcher)],env=env,cwd=str(root),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        sys.path.insert(0,str(run))
        for n in ('menu_policy','p011_json'):sys.modules.pop(n,None)
        spec=importlib.util.spec_from_file_location('subject',str(run/'menu_trial.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        gp=None
        try:
            orig=waituntil(lambda: m.stock_processes())
            if case=='preexisting-path':
                pathlib.Path(policy['MENU_LINK']).mkdir()
                try:m.inspect_device();raise AssertionError('must refuse existing path')
                except RuntimeError as e:assert 'already exists' in str(e)
                assert m.alive(m.refresh(orig[0]));summaries.append({'case':case,'pass':True});continue
            if case=='bad-parent':
                # Alter policy expectation, not any real/stock process.
                m.P.LAUNCHER=str(root/'different.sh');shutil.copy2(str(launcher),m.P.LAUNCHER)
                try:m.inspect_device();raise AssertionError('must refuse parent mismatch')
                except RuntimeError as e:assert 'parent' in str(e)
                assert m.alive(m.refresh(orig[0]));summaries.append({'case':case,'pass':True});continue
            app,parent,_,_=m.inspect_device();m.record_identity('original',app);m.record_identity('launcher',parent)
            m.atomic_text(str(run/'logs/boot-id.txt'),m.boot_id()+'\n');os.symlink(str(run),policy['LOCK'])
            # Shorten only test invocation. Real start() enforces 60..300 seconds.
            sec='30' if case in ('stop','worker-killed','guardian-killed','launcher-killed') else '1'
            gf=open(root/'guardian-output.log','wb')
            gp=subprocess.Popen([sys.executable,str(run/'menu_trial.py'),'guardian',sec],stdout=gf,stderr=gf,start_new_session=True)
            if case in ('stop','worker-killed','guardian-killed','launcher-killed'):
                waituntil(lambda: 'CANDIDATE_RUNNING:' in filetext(run/'logs/trial.log'))
                if case=='stop':m.atomic_text(str(run/'logs/stop.request'),'test\n')
                if case=='launcher-killed':
                    m.signal_exact(parent, signal.SIGKILL)
                if case=='worker-killed':
                    ident=m.get_identity('worker');m.signal_exact(ident,signal.SIGKILL)
                if case=='guardian-killed':
                    gp.kill();gp.wait();m.stop_trial()
            if case!='guardian-killed':gp.wait(timeout=22)
            gf.close()
            done=filetext(run/'logs/finished');text=filetext(run/'logs/trial.log')
            assert done.strip()=='RESTORED',(case,done,text,filetext(root/'guardian-output.log'))
            assert 'RESTORED_STOCK_PROCESS' in text,text
            assert len(m.stock_processes())==1
            assert not m.candidate_group()
            assert not os.path.lexists(policy['MENU_LINK'])
            assert not os.path.lexists(policy['LOCK'])
            if case=='busy-original':assert 'CANDIDATE_RUNNING' not in text,text
            if case=='candidate-stubborn':assert 'CANDIDATE_FORCE_EXIT' in text,text
            summaries.append({'case':case,'pass':True,'evidence':text.splitlines()})
        finally:
            if gp and gp.poll() is None:
                gp.terminate()
                try:gp.wait(timeout=12)
                except subprocess.TimeoutExpired:gp.kill();gp.wait()
            # Clean only test-owned app and private launcher session.
            for p in m.processes():
                if m.alive(p) and (p['exe'] in (str(stock),str(cand)) or p['sid']==lp.pid or m.launcher_matches(p)):
                    try:os.kill(p['pid'],signal.SIGKILL)
                    except ProcessLookupError:pass
            lp.wait(timeout=3);sk.close();sys.path.remove(str(run))
    print('PASS',case,flush=True)
result=PACKAGE/'tests'/('supervisor-results-'+ '-'.join(CASES)+'.json')
result.write_text(json.dumps({'scope':'Host Linux fake-process tests, NOT P011/Qt/Windows','cases':summaries},indent=2))
print('REPORT',result)
