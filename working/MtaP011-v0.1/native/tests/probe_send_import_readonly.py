"""P011 in-memory import and GET_INTERFACE compatibility check; no uploads/RF."""
from pathlib import Path
import base64
import sys
import zlib
BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'host'))
from device_probe import Adb

def main():
    if len(sys.argv) != 2: raise SystemExit('Usage: probe_send_import_readonly.py LOG_DIR')
    codec = (BASE / 'runtime' / 'p011_json.py').read_text(encoding='utf-8')
    helper = (BASE / 'runtime' / 'mta_send_wifi.py').read_text(encoding='utf-8')
    source = '''import sys,types
codec=types.ModuleType('p011_json')
exec(CODEC,codec.__dict__);sys.modules['p011_json']=codec
module=types.ModuleType('mta_send_wifi')
try:
 exec(HELPER,module.__dict__)
 library=module._libc()
 nl=module.ReadWriteNetlink()
 try: rows=nl.interfaces()
 finally:nl.close()
 result={'read_only':True,'import_ok':True,'get_interface_ok':True,'interface_count':len(rows),
   'existing_p2p_count':sum(r.get('iftype') in (8,9,10) for r in rows),
   'station_count':sum(r.get('name')=='wlan0' and r.get('iftype')==2 for r in rows),
   'libc_flock_setrlimit_available':hasattr(library,'flock') and hasattr(library,'setrlimit')}
except Exception as error:
 result={'read_only':True,'import_ok':False,'error_kind':type(error).__name__}
 if isinstance(error,ImportError):
  import re
  message=str(error)
  if re.match(r"^No module named '[A-Za-z0-9_.]+'$",message):result['missing_module']=message
print('RESULT='+repr(result))
'''
    payload = base64.b64encode(zlib.compress(('CODEC=' + repr(codec) + '\nHELPER=' + repr(helper) + '\n' + source).encode('utf-8'))).decode('ascii')
    chunks = [payload[i:i+512] for i in range(0, len(payload), 512)]
    bounded_source = 'import base64,zlib\ncompressed=(\n' + '\n'.join(repr(chunk) for chunk in chunks) + '\n)\nexec(zlib.decompress(base64.b64decode(compressed)))\n'
    result = Adb(sys.argv[1]).python('private-send-import-readonly', bounded_source)
    print(result)

if __name__ == '__main__': main()
