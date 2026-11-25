"""Bounded private kernel log observation after P2P failure; no RF action."""
import ast
import datetime
import hashlib
from pathlib import Path
import re
import secrets
import sys

from device_probe import Adb, BASE, ROOT

BODY = r'''
import hashlib,re,subprocess
stock=stock_snapshot();require_stock(stock)
process=subprocess.Popen(['dmesg'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:output,error=process.communicate(timeout=5)
except subprocess.TimeoutExpired:
 process.kill();process.communicate();raise ValueError('readonly_dmesg_timeout')
if process.returncode or len(output)>2097152 or len(error)>16384:raise ValueError('readonly_dmesg_failed')
lines=output.decode('utf-8','replace').splitlines()
driver=[line for line in lines if re.search(r'sprdwl|sprd_wlan|cfg80211|nl80211',line,re.I)]
indices=[i for i,line in enumerate(lines) if 'sprdwl_init_fw failed' in line][-4:]
selected=[line for i in indices for line in lines[max(0,i-6):min(len(lines),i+4)]]
after=stock_snapshot();require_stock(after)
print('RESULT='+repr({'stock_unchanged':stock==after,'log_sha256':hashlib.sha256(output).hexdigest(),
 'driver_line_count':len(driver),'selected_lines':selected,'radio_operations':False,
 'kernel_stdout_raw':output,'kernel_stderr_raw':error,'kernel_remote_exit':process.returncode}))
'''


def main():
    out=ROOT/'logs'/('MtaP011-P2pKernelReadOnly-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    safety=(BASE/'runtime/mta_safety.py').read_text(encoding='utf-8')
    source=safety+'\n'+BODY
    ast.parse(source,feature_version=(3,5))
    value=Adb(out/'private-raw').python('readonly-kernel-observation',source)
    if not isinstance(value,dict) or value.get('stock_unchanged') is not True:
        raise ValueError('Kernel observation stock gate failed')
    print('READONLY_STOCK_UNCHANGED=True')
    print('DRIVER_LINE_COUNT='+str(value['driver_line_count']))
    # Display a derived redacted view only. Original stdout stays private.
    for line in value['selected_lines']:
        line=re.sub(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b','[MAC]',line)
        line=re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','[IP]',line)
        line=re.sub(r'\bmta[0-9a-f]{8}\b','[OWNED_INTERFACE]',line)
        line=re.sub(r'(?i)\b(ssid|password|psk|imei|imsi)=[^\s,]+',r'\1=[REDACTED]',line)
        line=re.sub(r'([\"\']).*?\1','[QUOTED]',line)
        line=re.sub(r'\b[0-9a-fA-F]{32,}\b','[HEX]',line)
        print(line[:512])
    print('PRIVATE_RAW_DIRECTORY='+str(out))


if __name__=='__main__':main()
