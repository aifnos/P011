#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P011 radio incident collector v1.0, Python 3.5 compatible.

Read-only with respect to device configuration and services. Own diagnostic
files are created beside this script. No service start, discovery, pairing,
radio/USB toggle, process-group cleanup, partition access, or reboot.
Potentially blocking phases execute as separate bounded child processes.
"""
import os
import sys
import time
import re
import glob
import stat
import subprocess
import hashlib
import traceback
import p011_json as J

ROOT = os.path.realpath(os.path.dirname(__file__))
OUT = os.path.join(ROOT, 'result')
EXPECTED = {
    '/usr/bin/Z03': 'e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997',
    '/usr/bin/zyb_z03_launch.sh': '923a4cf73dc2f065fc565613676bf6f94a6a2c06e7d462c0a84dc6e020080edf'
}
RELEVANT = re.compile(r'connman|bluetooth|hciattach|wpa_supplicant|control_engine|sprdrild|ofonod|engpc|adbd|dbus-daemon|weston|^Z03$|zyb_z03|menu_trial|tools_bridge|radio_check|core_helper', re.I)
RADIO_LINE = re.compile(r'connman|bluetooth|\bhci\w*|wlan|sprdwl|sprd.*wcn|marlin|rfkill|wpa_supplicant|control_engine|firmware|segfault|segmentation|oom-kill|out of memory|killed process', re.I)
SECRET = re.compile(r'(?i)(\b(?:psk|passphrase|password|passwd|pin|pincode|linkkey|ltk|irk|token|authorization|cookie)\b\s*(?:[:=]|\bis\b)\s*)(?:"[^"]*"|\'[^\']*\'|\S+)')
MAC = re.compile(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])')


def redact(s):
    s = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(s))
    s = SECRET.sub(lambda m: m.group(1) + '<REDACTED>', s)
    return MAC.sub('<MAC_REDACTED>', s)


def read(path, limit=65536, tail=False):
    try:
        with open(path, 'rb') as f:
            if tail:
                f.seek(0, os.SEEK_END)
                n = f.tell()
                f.seek(max(0, n - limit))
            b = f.read(limit + 1)
        return b[:limit].decode('utf-8', 'replace')
    except (OSError, IOError) as e:
        return '[READ_ERROR: %s]' % str(e)


def save(name, obj):
    if not os.path.isdir(OUT):
        os.makedirs(OUT, 0o700)
    tmp = os.path.join(OUT, name + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(J.dumps(obj, indent=2))
        f.write('\n')
    os.replace(tmp, os.path.join(OUT, name))


def stamp():
    return {'device_epoch': time.time(), 'device_monotonic': time.monotonic(),
            'uptime': read('/proc/uptime', 128).strip(),
            'boot_id': read('/proc/sys/kernel/random/boot_id', 128).strip()}


def parse_stat(s):
    a = s.index('(')
    b = s.rindex(')')
    v = s[b + 2:].split()
    return {'pid': int(s[:a].strip()), 'comm': s[a + 1:b], 'state': v[0],
            'ppid': int(v[1]), 'pgrp': int(v[2]), 'sid': int(v[3]), 'start_ticks': int(v[19])}


def process_snapshot():
    found = []
    all_counts = {}
    for path in sorted(glob.glob('/proc/[0-9]*/stat')):
        try:
            info = parse_stat(read(path, 4096))
        except (ValueError, IndexError, KeyError):
            continue
        all_counts[info['state']] = all_counts.get(info['state'], 0) + 1
        pid = info['pid']
        comm = info['comm']
        # Read argv only for these relevant/possibly related processes. Never environ.
        if RELEVANT.search(comm) or comm in ('sh', 'bash', 'python3', 'python3.5', 'python'):
            args = read('/proc/%d/cmdline' % pid, 4096).replace('\0', ' ').strip()
            if not RELEVANT.search(comm + ' ' + args):
                continue
            info['argv'] = redact(args)
            try:
                info['exe'] = os.readlink('/proc/%d/exe' % pid)
            except OSError as e:
                info['exe_error'] = str(e)
            info['wchan'] = read('/proc/%d/wchan' % pid, 256).strip()
            info['status'] = '\n'.join(x for x in read('/proc/%d/status' % pid, 8192).splitlines()
                                       if x.split(':', 1)[0] in ('Name','State','Tgid','Pid','PPid','TracerPid','Uid','Gid','Threads','VmRSS','VmSize','SigPnd','ShdPnd'))
            if info['state'] in ('D', 'T', 't'):
                info['kernel_stack'] = redact(read('/proc/%d/stack' % pid, 4096))
            found.append(info)
    aliases = []
    for path in ('/mnt/data/p011-menu', '/tmp/p011-menutest.lock'):
        item = {'path': path, 'lexists': os.path.lexists(path)}
        if os.path.islink(path):
            item.update({'kind': 'symlink', 'target': os.readlink(path), 'resolved': os.path.realpath(path)})
        elif os.path.lexists(path):
            item['kind'] = 'directory' if os.path.isdir(path) else 'other'
        aliases.append(item)
    sessions = []
    roots = glob.glob('/tmp/p011-menutest-*')
    for path in sorted(roots)[-8:]:
        if not os.path.isdir(path):
            continue
        item = {'path': path, 'files': {}}
        for name in ('status.txt','finished','trial.log','guardian.log','worker.log',
                     'tools-finished.json','tools-recovery.json','candidate-identity-uncertain.json',
                     'candidate-identity-mismatch.json','boot-id.txt'):
            f = path + '/logs/' + name
            if os.path.isfile(f):
                item['files'][name] = redact(read(f, 32768, tail=True))
        # Do not collect Session.js, private auth keys, full argv environments, or USB backup.
        for name in ('guardian','worker','candidate','original','launcher','restored-stock'):
            for f in (path + '/logs/' + name + '.ident', path + '/logs/' + name + '.identity'):
                if os.path.isfile(f):
                    item['files'][os.path.relpath(f,path)] = read(f, 256)
        sessions.append(item)
    return {'stamp': stamp(), 'processes': found, 'all_process_state_counts': all_counts,
            'menu_aliases': aliases, 'trial_sessions': sessions}


def locate(name):
    for d in ('/usr/bin','/usr/sbin','/bin','/sbin'):
        p = d + '/' + name
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def run_read_command(args, seconds=3, limit=262144):
    p = None
    try:
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, close_fds=True,
                             env=dict(os.environ, LC_ALL='C'))
        try:
            out, err = p.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            p.kill()  # Only this collector's own read-command child, never a system daemon.
            try:
                out, err = p.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                return {'argv':args, 'timeout':True, 'child_wait_timeout':True}
            return {'argv':args, 'timeout':True, 'stdout':redact(out[:limit].decode('utf-8','replace')),
                    'stderr':redact(err[:4096].decode('utf-8','replace'))}
        return {'argv':args, 'exit':p.returncode, 'stdout':redact(out[:limit].decode('utf-8','replace')),
                'stderr':redact(err[:4096].decode('utf-8','replace')), 'truncated':len(out)>limit}
    except Exception as e:
        return {'argv':args, 'error':type(e).__name__+': '+str(e)}


def sys_network():
    interfaces = []
    for d in sorted(glob.glob('/sys/class/net/*')):
        info = {'name':os.path.basename(d)}
        for field in ('operstate','flags','carrier','mtu','ifindex','type','uevent'):
            info[field] = redact(read(d+'/'+field, 4096).strip())
        for path in ('device/driver','device/driver/module'):
            try:
                info[path] = os.path.realpath(d+'/'+path) if os.path.exists(d+'/'+path) else None
            except OSError:
                pass
        for field in ('rx_bytes','tx_bytes','rx_errors','tx_errors','rx_dropped','tx_dropped'):
            info[field] = read(d+'/statistics/'+field,128).strip()
        interfaces.append(info)
    rf = []
    for d in sorted(glob.glob('/sys/class/rfkill/rfkill*')):
        rf.append(dict([('path',d)]+[(k,read(d+'/'+k,256).strip()) for k in ('name','type','soft','hard','state')]))
    hci=[]
    for d in sorted(glob.glob('/sys/class/bluetooth/hci*')):
        hci.append({'name':os.path.basename(d), 'device':os.path.realpath(d+'/device'), 'uevent':redact(read(d+'/uevent',4096))})
    cmds=[]
    for name,args in (('ip',['-details','link','show']), ('ip',['-o','-4','addr','show']),
                      ('ip',['route','show']), ('hciconfig',['-a'])):
        p=locate(name)
        if p:cmds.append(run_read_command([p]+args,seconds=2))
    return {'stamp':stamp(),'interfaces':interfaces,'rfkill':rf,'bluetooth_sysfs':hci,
            'commands':cmds,'proc_net_dev':read('/proc/net/dev',16384),
            'proc_net_wireless':read('/proc/net/wireless',8192),
            'modules':read('/proc/modules',65536)}


def primitive(v):
    t=type(v).__name__
    if t=='Boolean':return bool(v)
    if isinstance(v,dict):return {str(k):primitive(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)):return [primitive(x) for x in v]
    if isinstance(v,str):return redact(v)
    if isinstance(v,(int,float,bool)) or v is None:return v
    return redact(str(v))


def bus_snapshot():
    result={'stamp':stamp(),'services':{},'queries':{},'auto_start_requested':False}
    try:
        import dbus
    except ImportError as e:
        result['error']=str(e)
        exe=locate('dbus-send')
        if exe:
            result['fallback']=run_read_command([exe,'--system','--print-reply','--reply-timeout=2000',
                '--dest=org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus.ListNames'],seconds=3)
        return result
    bus=dbus.SystemBus(private=True)
    try:
        def call(name,path,interface,member,signature='',args=()):
            # Unique-name calls cannot auto-start an absent radio daemon.
            return bus.call_blocking(name,path,interface,member,signature,args,timeout=2)
        owner_iface='org.freedesktop.DBus'
        for name in ('net.connman','org.bluez','fi.w1.wpa_supplicant1','fi.epitest.hostap.WPASupplicant','org.ofono'):
            item={}
            result['services'][name]=item
            try:
                has=bool(call(owner_iface,'/org/freedesktop/DBus',owner_iface,'NameHasOwner','s',(name,)))
                item['has_owner']=has
                if not has:continue
                owner=str(call(owner_iface,'/org/freedesktop/DBus',owner_iface,'GetNameOwner','s',(name,)))
                item['unique_owner']=owner
                item['pid']=int(call(owner_iface,'/org/freedesktop/DBus',owner_iface,'GetConnectionUnixProcessID','s',(owner,)))
                if name=='net.connman':
                    for method in ('GetProperties','GetTechnologies'):
                        try:
                            val=call(owner,'/','net.connman.Manager',method)
                            result['queries']['connman.'+method]=primitive(val)
                        except Exception as e:
                            result['queries']['connman.'+method]={'error':str(e)}
                    # No GetServices/Scan/Connect/SetProperty/StartServiceByName.
                if name=='org.bluez':
                    vals=call(owner,'/','org.freedesktop.DBus.ObjectManager','GetManagedObjects')
                    adapters=[];device_count=0;connected=0
                    for path,ifs in vals.items():
                        if 'org.bluez.Adapter1' in ifs:
                            props=ifs['org.bluez.Adapter1']
                            adapters.append({'path':str(path),'properties':{
                                k:primitive(props[k]) for k in ('Name','Powered','Discovering','Discoverable','Pairable','DiscoverableTimeout','PairableTimeout','UUIDs') if k in props}})
                        if 'org.bluez.Device1' in ifs:
                            device_count+=1
                            if ifs['org.bluez.Device1'].get('Connected'):connected+=1
                    result['queries']['bluez.adapters']=adapters
                    result['queries']['bluez.device_counts']={'cached_objects':device_count,'connected':connected,
                        'nearby_addresses_names_and_keys_collected':False}
            except Exception as e:
                item['error']=redact(str(e))
    finally:
        bus.close()
    return result


def path_metadata(path):
    item={'path':path,'exists':os.path.lexists(path)}
    try:
        s=os.lstat(path)
        item.update({'bytes':s.st_size,'mtime':s.st_mtime,'mode':oct(stat.S_IMODE(s.st_mode)),
                     'uid':s.st_uid,'gid':s.st_gid,'symlink':stat.S_ISLNK(s.st_mode)})
        if stat.S_ISLNK(s.st_mode):item['target']=os.readlink(path)
    except OSError as e:item['error']=str(e)
    return item


def file_snapshot():
    files=[]
    targets=list(EXPECTED)+['/usr/sbin/connmand','/usr/bin/connmand','/usr/libexec/bluetooth/bluetoothd',
        '/usr/lib/bluetooth/bluetoothd','/usr/sbin/bluetoothd','/usr/bin/control_engine']
    for p in targets:
        if not os.path.isfile(p):continue
        item=path_metadata(p);n=0;h=hashlib.sha256()
        with open(p,'rb') as f:
            while True:
                b=f.read(262144)
                if not b:break
                n+=len(b)
                if n>24*1024*1024:break
                h.update(b)
        if n<=24*1024*1024:
            item['sha256']=h.hexdigest()
            if p in EXPECTED:item['matches_original_backup']=h.hexdigest()==EXPECTED[p]
        files.append(item)
    init_files=[]
    seen=set()
    for pattern in ('/etc/init.d/*connman*','/etc/init.d/*blue*','/etc/init.d/*wpa*',
                    '/etc/init.d/*wcn*','/etc/init.d/*control*','/etc/init.d/*hci*',
                    '/etc/rc*.d/*connman*','/etc/rc*.d/*blue*',
                    '/usr/share/dbus-1/system-services/*connman*','/usr/share/dbus-1/system-services/*blue*',
                    '/etc/dbus-1/system.d/*connman*','/etc/dbus-1/system.d/*blue*'):
        for p in sorted(glob.glob(pattern))[:50]:
            if p in seen:continue
            seen.add(p); item=path_metadata(p)
            if os.path.isfile(p):item['content']=redact(read(p,32768))
            init_files.append(item)
    cores=[]
    for base in ('/mnt/data/coredump','/home/coredump','/var/coredump'):
        for p in sorted(glob.glob(base+'/*'))[:100]:
            if re.search('connman|bluetooth|hciattach|control_engine',os.path.basename(p),re.I):
                cores.append(path_metadata(p))
    configs=[]
    for p in ('/var/lib/connman/settings','/mnt/data/connman/settings','/home/connman/settings'):
        if os.path.isfile(p):
            lines=[]
            for l in read(p,65536).splitlines():
                if re.match(r'^\[',l) or re.match(r'(?i)^\s*(OfflineMode|Enable|Powered|State|DefaultAutoConnect)\s*=',l):
                    lines.append(redact(l))
            configs.append({'path':p,'filtered_settings':lines})
    return {'stamp':stamp(),'binaries':files,'init_and_dbus_service_files':init_files,
            'crash_file_metadata_only':cores,'connman_global_settings_filtered':configs,
            'os_release':read('/etc/os-release',8192),'mounts':read('/proc/mounts',65536),
            'core_pattern':read('/proc/sys/kernel/core_pattern',4096)}


def kernel_snapshot():
    result={'stamp':stamp(),'memory':read('/proc/meminfo',16384),'loadavg':read('/proc/loadavg',256),
            'sources':[]}
    exe=locate('dmesg')
    if exe:
        cmd=run_read_command([exe],seconds=3,limit=2*1024*1024)
        full=cmd.pop('stdout','');lines=full.splitlines()
        cmd['filtered_tail']=[redact(x) for x in lines if RADIO_LINE.search(x)][-400:]
        cmd['source']='dmesg (read only; no clear flag)'
        result['sources'].append(cmd)
    for p in ('/var/log/messages','/var/log/syslog','/var/volatile/log/messages','/var/volatile/log/syslog'):
        if not os.path.isfile(p):continue
        txt=read(p,256*1024,tail=True)
        result['sources'].append({'source':p,'filtered_tail':[redact(x) for x in txt.splitlines() if RADIO_LINE.search(x)][-300:]})
    return result

PHASES=[('process_before',process_snapshot,12),('bus_before',bus_snapshot,15),
        ('network',sys_network,12),('files',file_snapshot,15),('kernel',kernel_snapshot,10),
        ('bus_after',bus_snapshot,15),('process_after',process_snapshot,12)]


def main():
    if not os.path.isdir(OUT):os.makedirs(OUT,0o700)
    os.umask(0o077)
    if len(sys.argv)>2 and sys.argv[1]=='--phase':
        name=sys.argv[2]
        for k,fn,_ in PHASES:
            if k==name:
                try:save(k+'.json',fn())
                except Exception:
                    save(k+'.json',{'error':traceback.format_exc()})
                    return 2
                return 0
        return 3
    if len(sys.argv)!=1:raise ValueError('No commands or paths accepted')
    if os.getuid()!=0:
        save('collector.json',{'result':'NOT_ROOT','uid':os.getuid()});return 4
    results=[];begin=stamp();global_timer=time.monotonic()
    print('P011 radio read-only collector 1.0',flush=True)
    for name,_,budget in PHASES:
        if time.monotonic()-global_timer>95:
            results.append({'phase':name,'skipped':'collector time ceiling'});continue
        print('READ: '+name,flush=True)
        started=time.monotonic();code=None;timed=False;still=False
        with open(OUT+'/'+name+'-worker.txt','wb') as f:
            p=subprocess.Popen([sys.executable,'-B',__file__,'--phase',name],stdin=subprocess.DEVNULL,
                               stdout=f,stderr=f,close_fds=True)
            try:code=p.wait(timeout=budget)
            except subprocess.TimeoutExpired:
                timed=True;p.kill()
                try:code=p.wait(timeout=1)
                except subprocess.TimeoutExpired:still=True
        results.append({'phase':name,'exit':code,'timeout':timed,'child_still_pending':still,
                        'seconds':round(time.monotonic()-started,3),'output_present':os.path.isfile(OUT+'/'+name+'.json')})
    result='COMPLETE' if all(x.get('exit')==0 for x in results) else 'PARTIAL'
    save('collector.json',{'schema':'p011.radio_check.v1','result':result,'begin':begin,'end':stamp(),
        'phases':results,'operations':'read-only diagnostics; writes only own temporary reports',
        'privacy':'No network password files, paired-device keys, cores, auth files, complete process environments or user databases. System messages may still contain identifiers; review before sharing.'})
    print('COLLECT_RESULT: '+result,flush=True)
    return 0 if result=='COMPLETE' else 2

if __name__=='__main__':
    sys.exit(main())
