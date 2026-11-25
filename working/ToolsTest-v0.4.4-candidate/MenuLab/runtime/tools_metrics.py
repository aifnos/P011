# -*- coding: utf-8 -*-
"""Read-only diagnostics; Python 3.5. Missing driver data stays unavailable."""
import os, time, re, glob, subprocess

def text(path, limit=16384):
    try:
        with open(path,'rb') as f: return f.read(limit).decode('utf-8','replace').strip()
    except (OSError,IOError): return None

def tool(name):
    for d in ('/usr/bin','/usr/sbin','/bin','/sbin'):
        p=d+'/'+name
        if os.path.isfile(p) and os.access(p,os.X_OK): return p
    return None

def command(args, seconds=2):
    try:
        p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           close_fds=True,env=dict(os.environ,LC_ALL='C'))
        try: out,err=p.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            p.kill(); out,err=p.communicate(); return '', 'timeout: '+os.path.basename(args[0])
        if p.returncode: return '',err.decode('utf-8','replace')[:400] or 'exit='+str(p.returncode)
        return out.decode('utf-8','replace')[:32768].strip(),''
    except Exception as e: return '',type(e).__name__+': '+str(e)[:250]

def number(x):
    try:
        n=float(x)
        return n if abs(n)<1e16 else None
    except (TypeError,ValueError): return None

def scale(x,d):
    n=number(x); return round(n/d,3) if n is not None else None

def row(key,value,unit='',source='',note=''):
    valid=value is not None and value!=''
    return {'key':key,'value':str(value) if valid else '未提供','unit':unit if valid else '',
            'source':source,'note':note,'available':valid}

FIELDS=[('capacity','电量','%',1),('status','充放电状态','',None),('voltage_now','电池电压','V',1e6),
 ('current_now','电池侧电流','mA',1e3),('temp','电池温度','°C',10),('health','驱动健康状态','',None),
 ('technology','电池类型','',None),('present','电池存在','',1),('voltage_ocv','开路电压','V',1e6),
 ('voltage_min_design','设计最低电压','V',1e6),('voltage_max_design','设计最高电压','V',1e6),
 ('charge_now','当前电荷','mAh',1e3),('charge_full','最近满充电荷','mAh',1e3),
 ('charge_full_design','设计电荷','mAh',1e3),('charge_counter','电荷计数器','mAh',1e3),
 ('energy_now','当前能量','Wh',1e6),('energy_full','满充能量','Wh',1e6),
 ('energy_full_design','设计能量','Wh',1e6),('cycle_count','循环次数','次',1),
 ('time_to_empty_now','驱动预计剩余时间','s',1),('time_to_full_now','驱动预计充满时间','s',1),
 ('charge_type','充电类型','',None),('input_current_limit','输入电流限制','mA',1e3),
 ('constant_charge_current','充电电流设定','mA',1e3),('model_name','型号','',None),('manufacturer','制造商','',None)]

def battery(base='/sys/class/power_supply'):
    supplies=[]
    for p in sorted(glob.glob(base+'/*')):
        raw={}
        for k in [x[0] for x in FIELDS]+['online','type','usb_type']:
            v=text(p+'/'+k,128)
            if v is not None: raw[k]=v
        supplies.append({'name':os.path.basename(p),'type':raw.get('type'),'raw':raw})
    choices=[s for s in supplies if (s['type'] or '').lower()=='battery']
    if not choices: choices=[s for s in supplies if 'capacity' in s['raw']]
    main=choices[0] if choices else {'name':'未发现电池节点','raw':{}}
    d=main['raw']; rows=[]
    for k,label,unit,div in FIELDS:
        v=scale(d.get(k),div) if div else d.get(k)
        rows.append(row(label,v,unit,base+'/'+main['name']+'/'+k,
            '不是容量健康度百分比' if k=='health' else '保留驱动符号，不是充电器输入电流' if k=='current_now' else ''))
    v=scale(d.get('voltage_now'),1e6); a=scale(d.get('current_now'),1e3)
    power=round(v*a/1000,3) if v is not None and a is not None else None
    rows.insert(5,row('电池侧瞬时功率',power,'W','voltage_now × current_now','计算值，非 USB 输入功率'))
    full,design=number(d.get('charge_full')),number(d.get('charge_full_design'))
    soh=round(100*full/design,1) if full is not None and design and design>0 else None
    rows.append(row('满充 / 设计电荷比',soh,'%','charge_full / charge_full_design','估计值，受驱动标定影响'))
    for s in supplies:
        if s['name']==main['name']: continue
        for k,label,unit,div in [('online','在线','',None),('type','类型','',None),('voltage_now','电压','V',1e6),('current_now','电流','mA',1e3),('input_current_limit','输入电流限制','mA',1e3)]:
            if k in s['raw']: rows.append(row(s['name']+' · '+label,scale(s['raw'][k],div) if div else s['raw'][k],unit,'power_supply/'+s['name']+'/'+k))
    return {'node':main['name'],'capacity':number(d.get('capacity')),'status':d.get('status','未知'),
            'voltage':v,'current':a,'temperature':scale(d.get('temp'),10),'power':power,
            'rows':rows,'supplies':supplies,'epoch':time.time(),'monotonic':time.monotonic()}

def interfaces():
    ips={}; ip=tool('ip')
    if ip:
        out,_=command([ip,'-o','-4','addr','show'])
        for line in out.splitlines():
            m=re.search(r'^\d+:\s+(\S+)\s+inet\s+([0-9.]+)/\d+',line)
            if m: ips.setdefault(m.group(1).split('@')[0],[]).append(m.group(2))
    vals=[]
    for p in sorted(glob.glob('/sys/class/net/*')):
        name=os.path.basename(p)
        if not re.match(r'^[a-zA-Z0-9_.:-]{1,32}$',name): continue
        vals.append({'name':name,'state':text(p+'/operstate',40),'mac':text(p+'/address',64),'ipv4':ips.get(name,[]),
                     'wireless':os.path.isdir(p+'/wireless') or name.startswith(('wlan','mlan')),
                     'rx':number(text(p+'/statistics/rx_bytes',40)),'tx':number(text(p+'/statistics/tx_bytes',40)),
                     'rx_errors':number(text(p+'/statistics/rx_errors',40)),'tx_errors':number(text(p+'/statistics/tx_errors',40))})
    return vals

def private_ipv4(ip):
    try:
        p=[int(s) for s in ip.split('.')]
        return len(p)==4 and all(0<=n<=255 for n in p) and (p[0]==10 or (p[0]==172 and 16<=p[1]<=31) or (p[0]==192 and p[1]==168))
    except (ValueError,AttributeError): return False

def simple(v):
    if isinstance(v,dict): return {str(k):simple(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)): return [simple(x) for x in v]
    if type(v).__name__=='Boolean': return bool(v)
    if isinstance(v,(str,int,float,bool)) or v is None: return v
    return str(v)

def bluez_name(properties):
    # BlueZ Alias may default to a formatted address. Only Name is a name.
    name=properties.get('Name')
    if name is None: return None
    name=str(name).strip()
    return name or None

def bluez_scan_state():
    """Fresh adapter state for one bounded diagnostic; never starts discovery."""
    bus=None
    try:
        import dbus
        bus=dbus.SystemBus(private=True)
        adapter=bus.get_object('org.bluez','/org/bluez/hci0',introspect=False)
        properties=dbus.Interface(adapter,'org.freedesktop.DBus.Properties').GetAll('org.bluez.Adapter1',timeout=2)
        if 'Powered' not in properties or 'Discovering' not in properties:
            raise ValueError('missing adapter state')
        return {'available':True,'powered':bool(properties['Powered']),
                'discovering':bool(properties['Discovering']),'epoch':time.time()}
    except Exception as e:
        return {'available':False,'powered':False,'discovering':False,
                'epoch':time.time(),'error':type(e).__name__}
    finally:
        if bus is not None:
            try: bus.close()
            except Exception: pass

def radio():
    net=interfaces(); wifi=[]; cell=[]; bt=[]; errors=[]; dbus_ok=False
    for n in net:
        if n['name']=='lo': continue
        target=wifi if n['wireless'] else cell; prefix=n['name']+' · '
        target.extend([row(prefix+'状态',n['state']),row(prefix+'IPv4',', '.join(n['ipv4'])),
            row(prefix+'接收累计',scale(n['rx'],1048576),'MiB','sysfs接口统计'),row(prefix+'发送累计',scale(n['tx'],1048576),'MiB','sysfs接口统计'),
            row(prefix+'收 / 发错误',str(n['rx_errors'])+' / '+str(n['tx_errors']),'','sysfs接口统计')])
        iw=tool('iw')
        if n['wireless']:
            wifi.append(row(prefix+'MAC',n['mac']))
            if iw:
                out,err=command([iw,'dev',n['name'],'link'])
                for pattern,label,unit in [(r'Connected to (\S+)','BSSID',''),(r'SSID: (.+)','SSID',''),(r'freq: (.+)','频率','MHz'),(r'signal: (.+)','信号','驱动原始单位'),(r'tx bitrate: (.+)','协商发送速率','非实际网速'),(r'rx bitrate: (.+)','协商接收速率','非实际网速')]:
                    m=re.search(pattern,out)
                    if m: wifi.append(row(prefix+label,m.group(1),unit,'iw link'))
                if err: errors.append('iw: '+err)
    try:
        import dbus
        bus=dbus.SystemBus(private=True); dbus_ok=True
        # This firmware's connmand crashes when an external client introspects
        # net.connman.Manager. Wi-Fi is owned by control_engine/wpa_supplicant,
        # so the toolbox deliberately uses sysfs/ip/iw above and never queries it.
        errors.append('ConnMan：为避免触发本固件崩溃，工具箱不访问其 D-Bus 接口')
        try:
            manager=dbus.Interface(bus.get_object('org.ofono','/'),'org.ofono.Manager')
            for path,props in manager.GetModems(timeout=2):
                pr=simple(props)
                for k,l in [('Powered','基带供电'),('Online','基带在线'),('Manufacturer','基带厂商'),('Model','型号'),('Revision','基带版本')]:
                    if k in pr: cell.append(row(l,str(pr[k]),'','oFono.Modem'))
                for iface in ('org.ofono.NetworkRegistration','org.ofono.ConnectionManager'):
                    if iface not in pr.get('Interfaces',[]): continue
                    pp=simple(dbus.Interface(bus.get_object('org.ofono',path),iface).GetProperties(timeout=2))
                    for k,l in [('Status','注册状态'),('Mode','注册模式'),('Technology','网络制式'),('Name','运营商'),('Strength','信号质量'),('MobileCountryCode','MCC'),('MobileNetworkCode','MNC'),('LocationAreaCode','LAC/TAC'),('CellId','小区ID'),('Attached','数据附着'),('RoamingAllowed','允许漫游'),('Bearer','承载')]:
                        if k in pp: cell.append(row(l,str(pp[k]),'0–100，非 RSRP' if k=='Strength' else '',iface+'.'+k))
        except Exception as e: errors.append('oFono: '+str(e)[:200])
        try:
            bluez=bus.get_object('org.bluez','/',introspect=False)
            objs=dbus.Interface(bluez,'org.freedesktop.DBus.ObjectManager').GetManagedObjects(timeout=2)
            adapter_status=[];known_devices=[];device_count=0;named_count=0;detail_count=0
            for path,ifs in objs.items():
                device_name=bluez_name(simple(ifs.get('org.bluez.Device1',{})))
                include_details=bool(device_name) and detail_count<30
                if include_details:detail_count+=1
                for iface in ('org.bluez.Adapter1','org.bluez.Device1','org.bluez.Battery1'):
                    if iface not in ifs: continue
                    pr=simple(ifs[iface]);pre=pr.get('Alias') or pr.get('Name') or str(path).split('/')[-1]
                    if iface=='org.bluez.Adapter1':
                        for key,label in (('Powered','蓝牙供电'),('Discovering','蓝牙扫描中')):
                            if key in pr: adapter_status.append(row(label,'是' if pr[key] else '否','','BlueZ.Adapter1.'+key))
                    elif iface=='org.bluez.Device1':
                        device_count+=1
                        name=bluez_name(pr)
                        if name:
                            named_count+=1
                        if name and len(known_devices)<60:
                            signal=' · RSSI '+str(pr['RSSI'])+' dBm' if 'RSSI' in pr else ''
                            known_devices.append(row('已知设备',str(name)+signal,'','BlueZ.Device1','可能含历史缓存，非本次发现证明'))
                    if iface!='org.bluez.Adapter1' and not include_details:continue
                    for k,l in [('Name','名称'),('Address','地址'),('AddressType','地址类型'),('Powered','供电'),('Discovering','扫描中'),('Discoverable','可发现'),('Pairable','可配对'),('Paired','已配对'),('Connected','已连接'),('Trusted','已信任'),('RSSI','RSSI'),('TxPower','广播发射功率'),('UUIDs','服务UUID'),('Percentage','外设电量')]:
                        if k in pr: bt.append(row(pre+' · '+l,str(pr[k]),'dBm，可能为缓存' if k in ('RSSI','TxPower') else '%' if k=='Percentage' else '',iface+'.'+k))
            bt=adapter_status+[row('BlueZ 设备对象',device_count,'','BlueZ ObjectManager','全量计数，可能含历史缓存'),row('其中有 Name',named_count,'','BlueZ.Device1.Name','列出最多 60 个具名设备，明细最多 30 个；Name 不代表本次新发现')]+known_devices+bt
        except Exception as e: errors.append('BlueZ: '+str(e)[:200])
        try: bus.close()
        except Exception: pass
    except Exception as e: errors.append('Python D-Bus 不可用：'+str(e)[:200])
    if not dbus_ok:
        ds=tool('dbus-send')
        if ds:
            out,err=command([ds,'--system','--print-reply','--reply-timeout=1500','--dest=org.ofono','/','org.ofono.Manager.GetModems'])
            paths=re.findall(r'object path "(/[a-zA-Z0-9_/]+)"',out)
            for path in list(dict.fromkeys(paths))[:2]:
                out2,err2=command([ds,'--system','--print-reply','--reply-timeout=1500','--dest=org.ofono',path,'org.ofono.NetworkRegistration.GetProperties'])
                cell.append(row('网络注册原始属性',out2[:6000] or None,'','oFono D-Bus',err2))
        hc=tool('hciconfig')
        if hc:
            out,err=command([hc,'-a']);bt.append(row('蓝牙适配器',out or None,'','hciconfig -a',err))
    wifi.append(row('说明','仅读取状态，不主动扫描；协商速率不是实测网速'))
    for k in ('RSRP','RSRQ','SINR','LTE Band','EARFCN','PCI','邻区'):
        cell.append(row(k,None,'','当前已验证接口未提供','不从信号格数换算，不访问校准/NV接口'))
    cell.append(row('流量口径','非Wi-Fi接口计数不等于套餐剩余流量，可能含其他虚拟接口'))
    bt.append(row('说明','可请求原厂蓝牙扫描；列表可能含历史缓存，不自动配对或更改射频配置'))
    return {'wifi':wifi,'cell':cell,'bluetooth':bt,'interfaces':net,'errors':errors,'epoch':time.time(),'python_dbus':dbus_ok}

def capabilities():
    ts={n:tool(n) for n in ('sshd','ssh-keygen','iw','ip','connmanctl','dbus-send','hciconfig','gst-inspect-1.0','gst-play-1.0','mpg123','ffmpeg','pactl')};probes={}
    if ts['gst-inspect-1.0']:
        for elem in ('playbin','waylandsink','pulsesink','avdec_h264','qtdemux','mpegaudioparse'):
            out,err=command([ts['gst-inspect-1.0'],elem]);probes[elem]={'found':bool(out),'detail':out[:900],'error':err}
    return {'tools':ts,'gstreamer':probes,'kernel':os.uname().release,'architecture':os.uname().machine,
            'python':__import__('sys').version,'os_release':text('/etc/os-release',4096),'hardware_playback_tested':False}
