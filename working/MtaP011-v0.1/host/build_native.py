"""Build isolated native MTA helpers with the existing pinned ARM toolchain.

Only missing selected headers/libraries are read from P011 into a PRIVATE
link-only directory; none are installed on the pen or packaged for distribution.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from device_probe import Adb, BASE, ROOT, source

CONTAINER='p011-bili-build-20260923'
EXISTING=ROOT/'working/BiliP011-v0.1/private-gst-linksysroot'


def execute(argv):
    process=subprocess.run(argv,capture_output=True,timeout=90)
    if process.returncode:
        raise RuntimeError('Build step failed: '+process.stderr.decode('utf-8','replace')[-3000:])
    return process.stdout.decode('utf-8','replace')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect',action='store_true',help='Read the missing GIO library from the identified P011')
    args=parser.parse_args()
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out=BASE/'results'/('native-build-'+stamp);out.mkdir(parents=True)
    private=BASE/'private-linksysroot';private.mkdir(exist_ok=True)
    gio=private/'libgio-2.0.so.0.5400.3'
    selected=['/usr/lib/libgio-2.0.so.0.5400.3','/usr/lib/libffi.so.6.0.4',
              '/usr/lib/libpcre.so.1.2.9','/lib/libz.so.1.2.11',
              '/lib/libmount.so.1.1.0','/lib/libblkid.so.1.1.0','/lib/libuuid.so.1.3.0']
    if args.collect:
        adb=Adb(out/'private-raw');before=adb.python('before',source())
        if before['stock']['hashes']!=__import__('device_probe').PINS:
            raise RuntimeError('Stock firmware baseline differs')
        info=adb.python('link-identity',"import hashlib,os\npaths="+repr(selected)+"\nprint('RESULT='+repr([{'path':p,'size':os.path.getsize(p),'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()} for p in paths]))")
        for row in info:
            dest=private/Path(row['path']).name
            if not dest.exists():adb.run('pull-link',['pull',row['path'],str(dest)])
            if len(dest.read_bytes())!=row['size'] or hashlib.sha256(dest.read_bytes()).hexdigest()!=row['sha256']:
                raise RuntimeError('Target link library identity mismatch')
        after=adb.python('after',source())
        if before['stock']!=after['stock']:raise RuntimeError('Stock identity changed during read-only collection')
        (private/'PRIVATE_LINK_ONLY.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
    if not gio.is_file() or not (EXISTING/'usr/include/glib-2.0/gio/gio.h').is_file():
        raise RuntimeError('Missing verified target link-only dependencies; use --collect')
    workspace='/work/mta-native-'+stamp
    execute(['docker','exec',CONTAINER,'mkdir','-p',workspace+'/link',workspace+'/src'])
    execute(['docker','cp',str(BASE/'native')+'/.',CONTAINER+':'+workspace+'/src'])
    for path in selected:
        execute(['docker','cp',str(private/Path(path).name),CONTAINER+':'+workspace+'/link/'])
    includes=['-I/src/private-gst-linksysroot/usr/include/glib-2.0',
              '-I/src/private-gst-linksysroot/usr/lib/glib-2.0/include']
    old='/src/private-gst-linksysroot/usr/lib/'
    libraries=[workspace+'/link/'+gio.name]+[old+'lib'+n+'-2.0.so.0.5400.3' for n in ['gobject','gmodule','glib']]
    libraries += [workspace+'/link/'+Path(path).name for path in selected[1:]]
    results=[]
    binroot=BASE/'out/native';binroot.mkdir(parents=True,exist_ok=True)
    for name,files in [('mta-bluez-helper',['mta_core.c','mta_bluez_helper.c']),
                       ('mta-network-helper',['mta_core.c','mta_network.c']),
                       ('mta-wifi-caps',['mta_wifi_caps.c'])]:
        if not all((BASE/'native'/f).is_file() for f in files):continue
        target=workspace+'/'+name
        argv=(['docker','exec',CONTAINER,'arm-buildroot-linux-gnueabihf-gcc',
              '-std=c99','-O2','-fPIC','-march=armv7-a','-mfpu=neon','-mfloat-abi=hard',
              '-Wall','-Wextra','-Werror','-Wformat=2']+includes+
              [workspace+'/src/'+f for f in files]+['-o',target]+
              (libraries+['-Wl,-rpath-link,'+old,'-pthread'] if name!='mta-wifi-caps' else []))
        execute(argv)
        inspect=execute(['docker','exec',CONTAINER,'arm-buildroot-linux-gnueabihf-readelf','-h','-d',target])
        (out/(name+'.elf.txt')).write_text(inspect,encoding='utf-8')
        destination=binroot/name
        execute(['docker','cp',CONTAINER+':'+target,str(destination)])
        results.append({'name':name,'bytes':destination.stat().st_size,'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),
                        'target':'armv7-eabihf','compiled':True,'runtime':'NOT_TESTED'})
    report={'evidence_level':'HOST_CROSS_BUILD','helpers':results,'vendor_libraries_distributed':False}
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));print('RESULT_DIR='+str(out))


if __name__=='__main__':main()
