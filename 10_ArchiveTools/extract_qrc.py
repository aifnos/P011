#!/usr/bin/env python3
"""Offline, version-pinned QRC export from the owner's original Z03; no execution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import zlib

EXPECTED='e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997'
TREE,NAMES,DATA=0x18e8d4,0x190d04,0x194d5c
FONT_EXT={'.ttf','.otf','.ttc','.woff','.woff2','.eot','.pfa','.pfb','.fon','.pcf','.bdf'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    root=Path(__file__).resolve().parents[1]
    p.add_argument('--original',type=Path,default=root/'03_Source/vendor/Z03.original')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    raw=a.original.read_bytes()
    if len(raw)!=4001256 or hashlib.sha256(raw).hexdigest()!=EXPECTED:
        raise ValueError('Wrong Z03 version. Refusing to parse unknown offsets.')
    if a.out.exists():raise FileExistsError('Choose a new output directory')
    result=[]; seen=set()
    def walk(i,parent):
        if i in seen:raise ValueError('Tree cycle')
        seen.add(i);at=TREE+22*i
        no,flags=struct.unpack_from('>IH',raw,at)
        pos=NAMES+no;n=struct.unpack_from('>H',raw,pos)[0]
        name=raw[pos+6:pos+6+n*2].decode('utf-16-be')
        path=parent+'/'+name if parent else '/'+name
        if i==0:path=''
        if flags&2:
            count,first=struct.unpack_from('>II',raw,at+6)
            if count>10000:raise ValueError('Tree count invalid')
            for c in range(first,first+count):walk(c,path)
        else:
            offset=DATA+struct.unpack_from('>I',raw,at+10)[0]
            size=struct.unpack_from('>I',raw,offset)[0]
            data=raw[offset+4:offset+4+size]
            if len(data)!=size:raise ValueError('Truncated resource')
            if flags&1:
                size=struct.unpack_from('>I',data)[0];data=zlib.decompress(data[4:])
                if len(data)!=size:raise ValueError('Expanded length invalid')
            source=PurePosixPath(path.lstrip('/'))
            if '..' in source.parts:raise ValueError('Unsafe resource path')
            disk=re.sub(r'[<>:"\\|?*]',lambda m:'%{:02X}'.format(ord(m.group())),str(source))
            result.append((path,disk,data))
    walk(0,'')
    if len(result)!=400:raise ValueError('Expected 400 resource entries')
    a.out.mkdir(parents=True)
    manifest=[]
    for source,disk,data in result:
        exported=Path(disk).suffix.lower() not in FONT_EXT
        if exported:
            target=a.out/disk;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        manifest.append({'qrc':source,'path':disk,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'exported':exported})
    (a.out/'RESOURCE_MAP.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding='utf-8')
    print('400 resources parsed; standalone fonts excluded; target code was not executed.')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,struct.error,zlib.error) as e:
        print('STOP: '+str(e),file=sys.stderr);sys.exit(1)
