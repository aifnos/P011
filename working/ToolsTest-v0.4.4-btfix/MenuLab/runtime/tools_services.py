# -*- coding: utf-8 -*-
"""Allowlisted ADB config + isolated SSH. No general shell or reboot API.
Trial changes are journaled; configuration edited by someone else is never
blindly overwritten. Key files are private and outside the collected logs.
"""
import os, re, time, stat, signal, subprocess, hashlib, socket
import tools_metrics as M
import p011_json as J
CONFIG='/mnt/data/usbenum.ini'
def lease_clock():
    # Linux CLOCK_BOOTTIME includes suspend; a wrong wall clock cannot extend a lease.
    try:return time.clock_gettime(getattr(time,'CLOCK_BOOTTIME',7))
    except (AttributeError,OSError,ValueError):return time.monotonic()

DEBUG=re.compile(br'(?m)^([ \t]*debug[ \t]*=[ \t]*)([01])([ \t]*(?:[#;][^\r\n]*)?)(\r?)$')


def debug_field(raw):
    section = None
    property_sections = 0
    fields = []
    offset = 0
    for line in raw.splitlines(True):
        body = line.rstrip(b'\r\n')
        sec = re.match(br'^[ \t]*\[([^]\r\n]+)\][ \t]*(?:[#;].*)?$', body)
        if sec:
            section = sec.group(1).strip().lower()
            if section == b'property':
                property_sections += 1
        elif section == b'property':
            match = DEBUG.match(body)
            if match:
                fields.append((offset + match.start(2), offset + match.end(2), int(match.group(2))))
        offset += len(line)
    if property_sections != 1 or len(fields) != 1:
        raise RuntimeError('USB配置需要唯一的[property]段及debug=0/1字段；未改动')
    return fields[0]

def atomic(path,data,mode=0o600):
    tmp=path+'.new-'+str(os.getpid())
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    try:
        with os.fdopen(fd,'wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def readb(p,limit=65536):
    with open(p,'rb') as f: b=f.read(limit+1)
    if len(b)>limit: raise RuntimeError('文件长度超过固定上限')
    return b

def digest(b): return hashlib.sha256(b).hexdigest()

def proc(pid):
    try:
        r=M.text('/proc/%d/stat'%int(pid),8192);v=r[r.rfind(')')+2:].split()
        return {'pid':int(pid),'start':int(v[19]),'ppid':int(v[1]),'sid':int(v[3]),'state':v[0],
                'args':[os.fsdecode(x) for x in readb('/proc/%d/cmdline'%int(pid)).split(b'\0') if x],
                'exe':os.readlink('/proc/%d/exe'%int(pid))}
    except Exception: return None

def ps(): return [p for p in (proc(n) for n in os.listdir('/proc') if n.isdigit()) if p and p['state'] not in ('Z','X','x')]

def same(saved):
    p=proc(saved['pid']);return p if p and p['start']==saved['start'] and p['state'] not in ('Z','X','x') else None

def send(saved,sig):
    p=same(saved)
    if p and p['pid']>1 and p['pid']!=os.getpid(): os.kill(p['pid'],sig)

def replace_config(root,newbytes):
    private=root+'/private';os.makedirs(private,mode=0o700,exist_ok=True)
    st=os.lstat(CONFIG)
    if not stat.S_ISREG(st.st_mode): raise RuntimeError('USB配置不是普通文件，拒绝修改')
    now=readb(CONFIG)
    debug_field(now)
    debug_field(newbytes)
    backup=private+'/adb-original.ini';journal=private+'/adb-owned-hashes.txt'
    if not os.path.exists(backup): atomic(backup,now);atomic(journal,(digest(now)+'\n').encode('ascii'))
    owned=(M.text(journal) or '').splitlines()
    if digest(now) not in owned: raise RuntimeError('USB配置被其他程序改动，停止写入')
    owned.append(digest(newbytes));atomic(journal,('\n'.join(owned)+'\n').encode('ascii'))
    target=CONFIG+'.p011-tools-new'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,stat.S_IMODE(st.st_mode))
    try:
        with os.fdopen(fd,'wb') as f: f.write(newbytes);f.flush();os.fsync(f.fileno())
        os.chown(target,st.st_uid,st.st_gid);os.replace(target,CONFIG)
    finally:
        if os.path.exists(target): os.unlink(target)

def restore_adb(root):
    p=root+'/private/adb-original.ini'
    if not os.path.exists(p): return '未修改USB配置'
    original=readb(p);current=readb(CONFIG)
    if current==original:return 'USB配置已是原始值'
    owned=(M.text(root+'/private/adb-owned-hashes.txt') or '').splitlines()
    if digest(current) not in owned: raise RuntimeError('USB配置被外部更改，未覆盖，请保留日志')
    replace_config(root,original)
    if readb(CONFIG)!=original: raise RuntimeError('USB配置恢复校验失败')
    return 'USB配置已恢复到本次试验前的内容'

def recorded_ssh(root):
    vals=[]
    for line in (M.text(root+'/private/ssh-owned.tsv') or '').splitlines():
        v=line.split()
        if len(v)==2 and all(x.isdigit() for x in v):vals.append({'pid':int(v[0]),'start':int(v[1])})
    return vals

def cleanup_ssh(root):
    current=ps();saved=recorded_ssh(root)
    owned={(p['pid'],p['start']):p for p in current if any(p['pid']==q['pid'] and p['start']==q['start'] for q in saved)}
    for _ in range(12):
        old=len(owned);ids={p['pid'] for p in owned.values()}
        for p in current:
            if p['ppid'] in ids:owned[(p['pid'],p['start'])]=p
        if len(owned)==old:break
    for p in sorted(owned.values(),key=lambda x:x['pid'],reverse=True):send(p,signal.SIGTERM)
    until=lease_clock()+2
    while lease_clock()<until and any(same(p) for p in owned.values()):time.sleep(.08)
    for p in owned.values():
        if same(p):send(p,signal.SIGKILL)
    until=lease_clock()+1
    while lease_clock()<until and any(same(p) for p in owned.values()):time.sleep(.05)
    if any(same(p) for p in owned.values()):raise RuntimeError('本次SSH已识别进程尚未全部结束')
    return '本次SSH服务及已识别会话已关闭'

class Services:
    def __init__(self,root,logger):
        self.root=root;self.log=logger;self.private=root+'/private';os.makedirs(self.private,mode=0o700,exist_ok=True)
        self.child=None;self.deadline=0;self.last_track=0;self.bind='';self.mode='';self.error='';self.owned={}
        self.key=root+'/client.pub';self.hostpub='';self.fingerprint=''
        self.sshdir='/run/p011-tools-ssh/'+os.path.basename(root)
    def state(self):
        raw=readb(CONFIG) if os.path.isfile(CONFIG) else b''
        try:saved_value=debug_field(raw)[2]
        except RuntimeError:saved_value=None
        changed=os.path.isfile(self.private+'/adb-original.ini') and raw!=readb(self.private+'/adb-original.ini')
        return {'adb':{'saved':saved_value,
                       'daemon_running':any(os.path.basename(p['exe'])=='adbd' for p in ps()),'changed_by_trial':changed},
                'ssh':{'running':self.child is not None and self.child.poll() is None,'bind':self.bind,'port':2222,
                       'remaining':max(0,int(self.deadline-lease_clock())),'mode':self.mode,
                       'public_key_supplied':os.path.isfile(self.key),'host_fingerprint':self.fingerprint,
                       'error':self.error,'available':bool(M.tool('sshd') and M.tool('ssh-keygen')),'login_verified':False}}
    def adb_set(self,value):
        if value not in (0,1):raise ValueError('ADB只接受0或1')
        now=readb(CONFIG)
        start,end,_=debug_field(now)
        data=now[:start]+str(value).encode('ascii')+now[end:]
        replace_config(self.root,data);self.log('adb_saved_'+str(value))
        return {'message':'已保存ADB'+('开启' if value else '关闭')+'配置。本轮不重启，退出测试恢复原值。'}
    def save_connection(self):
        d={'running':self.child is not None and self.child.poll() is None,'address':self.bind,'port':2222,
           'mode':self.mode,'public_host_key':self.hostpub,'fingerprint':self.fingerprint,'epoch':time.time(),
           'auth':'publickey only','note':'监听状态，不代表认证登录已验证'}
        atomic(self.root+'/logs/ssh-connection.json',J.dumps(d,indent=2).encode('utf-8'))
    def tick(self):
        if not self.child:return
        if self.child.poll() is not None:
            self.error='sshd已退出，退出码 '+str(self.child.returncode);self.stop_ssh();return
        if lease_clock()>=self.deadline:
            self.log('ssh_lease_expired');self.stop_ssh();return
        if lease_clock()-self.last_track<1:return
        self.last_track=lease_clock()
        current=ps();ids={self.child.pid}
        for _ in range(10):
            old=len(ids)
            for p in current:
                if p['pid'] in ids or p['ppid'] in ids:
                    ids.add(p['pid']);self.owned[(p['pid'],p['start'])]=p
            if old==len(ids):break
        atomic(self.private+'/ssh-owned.tsv',(''.join('%d %d\n'%k for k in self.owned)).encode('ascii'))
        if lease_clock()>=self.deadline:self.log('ssh_lease_expired');self.stop_ssh()
    def stop_ssh(self):
        cleanup_ssh(self.root)
        if self.child:
            try:self.child.wait(timeout=1)
            except Exception:pass
        self.child=None;self.deadline=0;self.log('ssh_stopped');self.save_connection()
        return {'message':'本次SSH服务与已识别会话已停止'}
    def start_ssh(self,mode):
        if self.child and self.child.poll() is None:raise RuntimeError('请先关闭本次SSH，再切换监听方式')
        sshd=M.tool('sshd');keygen=M.tool('ssh-keygen')
        if not sshd or not keygen:raise RuntimeError('缺少sshd或ssh-keygen，未安装/修改系统软件')
        if not os.path.isfile(self.key):raise RuntimeError('没有电脑公钥，请检查SSH_KEY提示后重新运行测试')
        pub=readb(self.key,8192).decode('ascii','strict').strip().split()
        if len(pub)<2 or pub[0]!='ssh-ed25519' or not re.match(r'^[A-Za-z0-9+/]+={0,2}$',pub[1]):raise RuntimeError('仅接受Ed25519公钥，不接受私钥/authorized_keys选项')
        if mode=='usb':bind='127.0.0.1'
        elif mode=='wifi':
            choices=[ip for n in M.interfaces() if n['wireless'] and n['state']=='up' for ip in n['ipv4'] if M.private_ipv4(ip)]
            if not choices:raise RuntimeError('没有Wi-Fi私网IPv4，不会回退到4G/全网卡监听')
            bind=choices[0]
        else:raise ValueError('不允许的SSH模式')
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:sock.bind((bind,2222))
        except OSError:raise RuntimeError('2222端口已占用，不会停止已有服务')
        finally:sock.close()
        # OpenSSH StrictModes checks parent directories; /tmp is world-writable.
        for path in ('/run/p011-tools-ssh',self.sshdir):
            if not os.path.exists(path):os.mkdir(path,0o700)
            st=os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('SSH密钥目录权限不符合要求，不放宽StrictModes')
        auth=self.sshdir+'/authorized_keys';host=self.sshdir+'/host_ed25519'
        atomic(auth,(' '.join(pub[:2])+'\n').encode('ascii'))
        if not os.path.isfile(host):
            out,err=M.command([keygen,'-q','-t','ed25519','-N','','-f',host],8)
            if err or not os.path.isfile(host):raise RuntimeError('生成试验主机密钥失败：'+err)
        os.chmod(host,0o600);self.hostpub=readb(host+'.pub',4096).decode('ascii').strip()
        self.fingerprint=M.command([keygen,'-lf',host+'.pub'])[0]
        cfg=self.sshdir+'/sshd_config'
        lines=['Port 2222','AddressFamily inet','ListenAddress '+bind,'HostKey '+host,'PidFile '+self.sshdir+'/sshd.pid',
          'AuthorizedKeysFile '+auth,'StrictModes yes','PermitRootLogin prohibit-password','AllowUsers root',
          'PubkeyAuthentication yes','PasswordAuthentication no','ChallengeResponseAuthentication no','PermitEmptyPasswords no',
          'UsePAM no','AllowAgentForwarding no','AllowTcpForwarding no','X11Forwarding no','PermitTunnel no',
          'PermitUserEnvironment no','LoginGraceTime 20','MaxAuthTries 3','MaxSessions 2','MaxStartups 3:30:5',
          'ClientAliveInterval 20','ClientAliveCountMax 2','PrintMotd no','PrintLastLog no','LogLevel VERBOSE','Subsystem sftp internal-sftp']
        atomic(cfg,('\n'.join(lines)+'\n').encode('ascii'))
        if not os.path.exists('/var/run/sshd'):
            try:os.mkdir('/var/run/sshd',0o755)
            except OSError:pass
        out,err=M.command([sshd,'-t','-f',cfg],4)
        if err:self.error=err;raise RuntimeError('sshd配置检查失败，未启动：'+err)
        with open(os.devnull,'rb') as inp,open(self.root+'/logs/ssh.log','ab',buffering=0) as out:
            self.child=subprocess.Popen([sshd,'-D','-e','-f',cfg],stdin=inp,stdout=out,stderr=out,close_fds=True,start_new_session=True)
        p=proc(self.child.pid)
        if p:self.owned[(p['pid'],p['start'])]=p
        self.bind=bind;self.mode=mode;self.deadline=lease_clock()+300;self.error=''
        self.tick();time.sleep(.3)
        if self.child is None or self.child.poll() is not None:
            self.error=(M.text(self.root+'/logs/ssh.log') or '')[-1000:];raise RuntimeError('sshd启动失败，见ssh.log，未修改系统账号/密码')
        self.save_connection();self.log('ssh_started_'+mode)
        return {'message':'SSH已启动，最长5分钟或试验结束时关闭。尚未验证登录。'}
    def close(self):
        errors=[]
        try:self.stop_ssh()
        except Exception as e:errors.append(str(e))
        try:self.log('adb_restore: '+restore_adb(self.root))
        except Exception as e:errors.append(str(e))
        return errors

def emergency_cleanup(root):
    errors=[]
    try:cleanup_ssh(root)
    except Exception as e:errors.append('SSH: '+str(e))
    try:restore_adb(root)
    except Exception as e:errors.append('ADB: '+str(e))
    return errors
