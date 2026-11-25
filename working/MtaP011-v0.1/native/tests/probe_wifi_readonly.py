"""Run transient in-memory P011 read-only Wi-Fi queries, without uploading files.

IDs are supplied by mta-wifi-caps --ids compiled against Linux UAPI headers.
No radio writes, scan commands, SSID/MAC/network credentials, or raw peer output.
Private raw logs are retained by device_probe.Adb; only sanitized JSON is printed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'host'))
from device_probe import Adb

SOURCE = r'''
import os,re,socket,struct,subprocess,time
result={'read_only':True}
def command(argv):
 try:
  p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  out,err=p.communicate(timeout=5)
  return p.returncode,out.decode('utf-8','replace'),err.decode('utf-8','replace')
 except (OSError,subprocess.TimeoutExpired):
  try:p.kill();p.communicate()
  except Exception:pass
  return -1,'',''
def prop(path,interface,name):
 return command(['dbus-send','--system','--print-reply','--dest=fi.w1.wpa_supplicant1',path,
  'org.freedesktop.DBus.Properties.Get','string:'+interface,'string:'+name])
def error_name(text):
 match=re.search(r'Error ([A-Za-z0-9_.]+):',text)
 return match.group(1) if match else None
code,text,err=prop('/fi/w1/wpa_supplicant1','fi.w1.wpa_supplicant1','Capabilities')
allowed={'ap','ibss-rsn','p2p','interworking','mesh','tdls','eap','wpa','wpa2','wep','rsn','bss','sta'}
strings=re.findall(r'string "([^"\n]*)"',text)
result['supplicant_global_capabilities']={'query_ok':code==0,'values':[x for x in strings if x in allowed],
 'unknown_value_count':sum(x not in allowed for x in strings)}
code,text,err=command(['dbus-send','--system','--print-reply','--dest=org.freedesktop.DBus',
 '/org/freedesktop/DBus','org.freedesktop.DBus.GetConnectionUnixProcessID','string:fi.w1.wpa_supplicant1'])
match=re.search(r'uint32 ([0-9]+)',text);bus_pid=int(match.group(1)) if code==0 and match else None
instances=[]
for pid in os.listdir('/proc'):
 if not pid.isdigit():continue
 try:
  if open('/proc/'+pid+'/comm').read().strip()!='wpa_supplicant':continue
  argv=open('/proc/'+pid+'/cmdline','rb').read().split(b'\0')
  instances.append({'bus_owner':int(pid)==bus_pid,'uses_system_binary':os.readlink('/proc/'+pid+'/exe')=='/usr/sbin/wpa_supplicant',
   'u_flag':b'-u' in argv,'wlan0_flag':any(x in (b'-iwlan0',b'wlan0') for x in argv),
   'global_ctrl_flag':b'-g' in argv or any(x.startswith(b'-g') for x in argv[1:])})
 except OSError:pass
result['supplicant_instances']={'bus_pid_query_ok':bus_pid is not None,'instances':instances}
code,text,err=command(['dbus-send','--system','--print-reply','--dest=fi.w1.wpa_supplicant1',
 '/fi/w1/wpa_supplicant1','fi.w1.wpa_supplicant1.GetInterface','string:wlan0'])
paths=re.findall(r'object path "(/fi/w1/wpa_supplicant1/Interfaces/[0-9]+)"',text)
result['supplicant_existing_interface']={'query_ok':code==0,'found':len(paths)==1,'error_name':error_name(err)}
icode,itext,ierr=prop('/fi/w1/wpa_supplicant1','fi.w1.wpa_supplicant1','Interfaces')
registered=re.findall(r'object path "(/fi/w1/wpa_supplicant1/Interfaces/[0-9]+)"',itext)
result['supplicant_registered_interfaces']={'query_ok':icode==0,'count':len(registered),'error_name':error_name(ierr)}
rcode,rtext,rerr=command(['dbus-send','--system','--print-reply','--dest=fi.w1.wpa_supplicant1',
 '/fi/w1/wpa_supplicant1','org.freedesktop.DBus.Introspectable.Introspect'])
result['supplicant_root_api']={'query_ok':rcode==0,'has_get_interface':bool(re.search(r'name=\\?"GetInterface\\?"',rtext)),
 'has_p2p_interface_namespace':'fi.w1.wpa_supplicant1.Interface.P2PDevice' in rtext}
if len(paths)!=1 and len(registered)==1:paths=registered
if len(paths)==1:
 code,text,err=command(['dbus-send','--system','--print-reply','--dest=fi.w1.wpa_supplicant1',paths[0],
  'org.freedesktop.DBus.Introspectable.Introspect'])
 result['supplicant_existing_interface']['p2p_dbus_api']=code==0 and 'fi.w1.wpa_supplicant1.Interface.P2PDevice' in text
 code,text,err=prop(paths[0],'fi.w1.wpa_supplicant1.Interface','Capabilities')
 strings=re.findall(r'string "([^"\n]*)"',text)
 result['supplicant_interface_caps']={'query_ok':code==0,'p2p_value':any(x.lower()=='p2p' for x in strings),
   'mode_values':[x for x in strings if x.lower() in ('infrastructure','adhoc','ap','p2p','mesh')]}
code,text,err=command(['/usr/sbin/wpa_cli','-i','wlan0','help'])
result['wpa_cli_help']={'query_ok':code==0,'client_p2p_group_add':bool(re.search(r'(?m)^\s*p2p_group_add\b',text)),
 'client_p2p_find':bool(re.search(r'(?m)^\s*p2p_find\b',text)),'not_server_build_proof':True}
code,text,err=command(['/usr/sbin/wpa_cli','-i','wlan0','get_capability','modes'])
result['wpa_modes']={'query_ok':code==0,'values':[x for x in text.strip().split() if x in ('IBSS','AP','P2P','MESH')],
 'not_p2p_absence_proof':True}
def attrs(blob):
 out=[];at=0
 while at<len(blob):
  if len(blob)-at<4:raise ValueError('short_attr')
  n,t=struct.unpack_from('HH',blob,at);step=(n+3)&~3
  if n<4 or step>len(blob)-at:raise ValueError('bad_attr')
  out.append((t&0x3fff,blob[at+4:at+n]));at+=step
 return out
def uint(blob):
 if len(blob)!=4:raise ValueError('bad_u32')
 return struct.unpack('I',blob)[0]
names={1:'adhoc',2:'station',3:'ap',4:'ap_vlan',6:'monitor',7:'mesh',8:'p2p_client',9:'p2p_go',10:'p2p_device'}
def types(blob):
 return [names.get(t,'iftype_'+str(t)) for t,v in attrs(blob) if not v]
def request(s,family,cmd,flags,seq,blob=b''):
 header=struct.pack('IHHII',20+len(blob),family,1|flags,seq,0)
 s.sendto(header+struct.pack('BBH',cmd,1,0)+blob,(0,0))
def receive(s,seq,done=False):
 out=[];deadline=time.monotonic()+5;bytes_read=0;rounds=0
 while time.monotonic()<deadline:
  s.settimeout(max(.01,deadline-time.monotonic()))
  blob,anc,flags,sender=s.recvmsg(262144)
  rounds+=1;bytes_read+=len(blob)
  if flags&socket.MSG_TRUNC or sender[0]!=0 or bytes_read>1048576 or rounds>256:raise ValueError('receive_limit')
  at=0
  while at<len(blob):
   if len(blob)-at<16:raise ValueError('short_message')
   n,t,f,q,p=struct.unpack_from('IHHII',blob,at);step=(n+3)&~3
   if n<16 or step>len(blob)-at or q!=seq or f&16:raise ValueError('invalid_message')
   body=blob[at+16:at+n];at+=step
   if t==2:
    e=struct.unpack_from('i',body)[0]
    if e:raise OSError(-e,'netlink_error')
   elif t==3:
    if len(body)>=4:
     e=struct.unpack_from('i',body)[0]
     if e:raise OSError(abs(e),'netlink_done_error')
    return out
   else:
    if len(body)<4:raise ValueError('short_genl')
    out.append((t,body[0],body[4:]))
    if not done:return out
 raise OSError(110,'netlink_timeout')
try:
 s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,16);s.bind((0,0))
 family_name=b'nl80211\0';blob=struct.pack('HH',4+len(family_name),2)+family_name
 request(s,16,3,0,1,blob)
 family=None
 for t,cmd,body in receive(s,1):
  if t!=16:raise ValueError('controller_type')
  for a,v in attrs(body):
   if a==1 and len(v)==2:family=struct.unpack('H',v)[0]
 if not family:raise ValueError('no_family')
 request(s,family,IDS['get_wiphy'],0x300,2)
 phys={}
 for t,cmd,body in receive(s,2,True):
  if t!=family or cmd!=IDS['new_wiphy']:raise ValueError('wiphy_type')
  rows=attrs(body);indexes=[uint(v) for a,v in rows if a==IDS['wiphy']]
  if len(indexes)!=1:raise ValueError('wiphy_index')
  index=indexes[0]
  if index not in phys:
   if len(phys)>=8:raise ValueError('phy_limit')
   phys[index]={'index':index,'iftypes':[],'software_iftypes':[],'combinations':[],
    'iftypes_present':False,'combinations_present':False,'commands':{}}
  phy=phys[index]
  for a,v in rows:
   if a==IDS['supported_iftypes']:phy['iftypes_present']=True;phy['iftypes']=sorted(set(phy['iftypes']+types(v)))
   elif a==IDS['software_iftypes']:phy['software_iftypes']=sorted(set(phy['software_iftypes']+types(v)))
   elif a==IDS['supported_commands']:
    commands={uint(cv) for ca,cv in attrs(v)}
    for name in ('start_p2p_device','new_interface','start_ap'):phy['commands'][name]=IDS[name] in commands
   elif a==IDS['interface_combinations']:
    phy['combinations_present']=True
    for ci,cv in attrs(v):
     combo={'limits':[]}
     for ca,cb in attrs(cv):
      if ca==IDS['comb_maxnum']:combo['max_interfaces']=uint(cb)
      elif ca==IDS['comb_channels']:combo['num_channels']=uint(cb)
      elif ca==IDS['comb_limits']:
       for li,lv in attrs(cb):
        limit={}
        for la,lb in attrs(lv):
         if la==IDS['limit_max']:limit['max']=uint(lb)
         elif la==IDS['limit_types']:limit['types']=types(lb)
        if set(limit)!=set(['max','types']):raise ValueError('missing_limit')
        combo['limits'].append(limit)
     if set(combo)!=set(['limits','max_interfaces','num_channels']):raise ValueError('missing_combination')
     if len(combo['limits'])>16 or len(phy['combinations'])>=16:raise ValueError('combination_limit')
     requirements={'station':1,'p2p_go':1}
     covered=set(x for l in combo['limits'] for x in l['types'])
     combo['station_plus_go_same_channel']=(combo['max_interfaces']>=2 and combo['num_channels']>=1 and
       set(requirements).issubset(covered) and all(sum(requirements.get(x,0) for x in l['types'])<=l['max'] for l in combo['limits']))
     requirements={'station':1,'ap':1}
     combo['station_plus_ap_same_channel']=(combo['max_interfaces']>=2 and combo['num_channels']>=1 and
       set(requirements).issubset(covered) and all(sum(requirements.get(x,0) for x in l['types'])<=l['max'] for l in combo['limits']))
     phy['combinations'].append(combo)
 result['nl80211']={'query_ok':True,'phys':[phys[k] for k in sorted(phys)]}
 s.close()
except (OSError,ValueError,struct.error) as e:
 result['nl80211']={'query_ok':False,'error_kind':type(e).__name__,'errno':getattr(e,'errno',None)}
 try:s.close()
 except Exception:pass
print('RESULT='+repr(result))
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ids-json', required=True,
                        help='JSON output of the host-compiled mta-wifi-caps --ids')
    parser.add_argument('--log-dir', required=True)
    args = parser.parse_args()
    ids = json.loads(args.ids_json)
    if not isinstance(ids, dict) or any(not isinstance(v, int) or not 0 < v < 1000 for v in ids.values()):
        raise ValueError('Invalid numeric UAPI IDs')
    adb = Adb(args.log_dir)
    source = 'IDS=' + repr(ids) + '\n' + SOURCE
    result = adb.python('wifi-caps-readonly', source)
    output = json.dumps(result, ensure_ascii=True, indent=2)
    (Path(args.log_dir) / 'wifi-caps.sanitized.json').write_text(output, encoding='utf-8')
    print(output)

if __name__ == '__main__':
    main()
