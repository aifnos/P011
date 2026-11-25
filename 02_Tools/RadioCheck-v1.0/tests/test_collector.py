import sys,os,json,ast,tempfile,types,importlib.util,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import radio_check as R
cases=[]
def case(name,fn):
 fn();cases.append({'name':name,'passed':True})
def expect(a,b):
 assert a==b,(a,b)
case('python35 grammar radio_check',lambda:ast.parse((ROOT/'runtime/radio_check.py').read_text(),feature_version=(3,5)))
case('python35 grammar local encoder',lambda:ast.parse((ROOT/'runtime/p011_json.py').read_text(),feature_version=(3,5)))
case('proc stat parser current host self',lambda:expect(R.parse_stat(pathlib.Path('/proc/self/stat').read_text())['pid'],os.getpid()))
case('JSON output roundtrip',lambda:expect(json.loads(R.J.dumps({'test':['中文',True,False,None,2,2.5]},indent=2)),{'test':['中文',True,False,None,2,2.5]}))
case('MAC masking',lambda:expect(R.redact('mac 12:34:56:78:ab:cd'),'mac <MAC_REDACTED>'))
case('password masking',lambda:expect(R.redact('password="abc def"'),'password=<REDACTED>'))
case('PSK masking',lambda:expect(R.redact('psk=0123456789'),'psk=<REDACTED>'))
case('ANSI removed',lambda:expect(R.redact('\x1b[31mhello\x1b[0m'),'hello'))
case('missing file preserved as error',lambda:expect(R.read('/__p011_missing__').startswith('[READ_ERROR:'),True))
allowed={'NameHasOwner','GetNameOwner','GetConnectionUnixProcessID','GetProperties','GetTechnologies','GetManagedObjects'}
class FakeBus:
 def __init__(self,cm): self.cm=cm;self.calls=[];self.closed=False
 def call_blocking(self,name,path,iface,method,signature,args,timeout):
  assert method in allowed,method
  self.calls.append((name,method,args))
  if method=='NameHasOwner':return args[0]=='org.bluez' or (self.cm and args[0]=='net.connman')
  if method=='GetNameOwner':return ':1.12' if args[0]=='org.bluez' else ':1.13'
  if method=='GetConnectionUnixProcessID':return 123
  if method=='GetProperties':return {'State':'idle','OfflineMode':False}
  if method=='GetTechnologies':return [('/net/connman/technology/wifi',{'Type':'wifi','Powered':False})]
  if method=='GetManagedObjects':return {'/org/bluez/hci0':{'org.bluez.Adapter1':{'Powered':True,'Discovering':True,'Name':'BlueZ'}},'/org/bluez/hci0/dev_01':{'org.bluez.Device1':{'Address':'secret','Alias':'private nearby','Connected':False}}}
  raise AssertionError(method)
 def close(self):self.closed=True

def test_bus(cm):
 fake=FakeBus(cm);prior=sys.modules.get('dbus');sys.modules['dbus']=types.SimpleNamespace(SystemBus=lambda private:fake)
 try:
  obj=R.bus_snapshot()
  expect(obj['services']['net.connman']['has_owner'],cm)
  expect(obj['queries']['bluez.adapters'][0]['properties']['Powered'],True)
  expect(obj['queries']['bluez.adapters'][0]['properties']['Discovering'],True)
  assert 'private nearby' not in R.J.dumps(obj) and 'secret' not in R.J.dumps(obj)
  assert all(name.startswith(':') for name,method,args in fake.calls if method not in ('NameHasOwner','GetNameOwner','GetConnectionUnixProcessID'))
  if not cm:assert not any(method in ('GetTechnologies','GetProperties') for _,method,_ in fake.calls)
  expect(fake.closed,True)
 finally:
  if prior is not None:sys.modules['dbus']=prior
  else:sys.modules.pop('dbus',None)
case('absent ConnMan not activated; BlueZ snapshot filtered',lambda:test_bus(False))
case('present ConnMan queried by unique name only',lambda:test_bus(True))
case('read command success',lambda:expect(R.run_read_command(['/bin/echo','hello'])['stdout'],'hello\n'))
case('read command timeout bounded',lambda:expect(R.run_read_command([sys.executable,'-c','import time;time.sleep(2)'],seconds=.1)['timeout'],True))
# Collector imports with the standard json module deliberately unavailable.
cmd='import builtins;old=builtins.__import__;\ndef imp(n,*a,**k):\n if n=="json" or n.startswith("json."):raise ImportError("simulated missing json")\n return old(n,*a,**k)\nbuiltins.__import__=imp\nimport radio_check\nprint(radio_check.J.dumps({"ok":True}))'
r=R.run_read_command([sys.executable,'-c',cmd]);expect(r.get('exit'),0)
cases.append({'name':'imports without standard json','passed':True})
record={'scope':'Linux host unit tests and mocked D-Bus; no Windows or P011 hardware run',
        'tests':cases,'passed':len(cases),'windows_executed':False,'p011_executed':False}
(ROOT/'tests/validation.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
print('PASS',len(cases),'host tests')
