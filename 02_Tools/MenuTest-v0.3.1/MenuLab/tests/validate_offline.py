#!/usr/bin/env python3
"""Offline firmware/resource checks. Never opens USB or executes target code.
Usage: python validate_offline.py --original PATH_TO_ORIGINAL_Z03
"""
import argparse, hashlib, json, re, struct, subprocess, sys, tempfile, zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TREE=0x18e8d4; NAMES=0x190d04; DATA=0x194d5c
sha=lambda b:hashlib.sha256(b).hexdigest()
def resource_map(binary):
    result={}; seen=set()
    def walk(i,prefix):
        if i in seen: raise ValueError('Resource tree cycle')
        seen.add(i)
        at=TREE+22*i
        no,flags=struct.unpack_from('>IH',binary,at)
        pos=NAMES+no; n=struct.unpack_from('>H',binary,pos)[0]
        name=binary[pos+6:pos+6+n*2].decode('utf-16-be')
        path=prefix+'/'+name if prefix else '/'+name
        if i==0:path=''
        if flags&2:
            count,first=struct.unpack_from('>II',binary,at+6)
            if count>10000:raise ValueError('Invalid tree count')
            for child in range(first,first+count):walk(child,path)
        else:
            rel=struct.unpack_from('>I',binary,at+10)[0]
            p=DATA+rel; size=struct.unpack_from('>I',binary,p)[0]
            data=binary[p+4:p+4+size]
            if len(data)!=size:raise ValueError('Truncated resource')
            if flags&1:
                expected=struct.unpack_from('>I',data)[0]; data=zlib.decompress(data[4:])
                if len(data)!=expected:raise ValueError('Invalid resource expansion length')
            result[path]=data
    walk(0,'');return result

def lexical_balance(text):
    """Only bracket/string/comment checking, NOT a QML parser/runtime test."""
    stack=[];quote=None;i=0
    while i<len(text):
        c=text[i]
        if quote:
            if c=='\\':i+=2;continue
            if c==quote:quote=None
            i+=1;continue
        if c in "\"'":quote=c;i+=1;continue
        if text.startswith('//',i):
            j=text.find('\n',i); i=len(text) if j<0 else j;continue
        if text.startswith('/*',i):
            j=text.find('*/',i+2)
            if j<0:raise AssertionError('Unclosed comment')
            i=j+2;continue
        if c in '{[(':stack.append(c)
        elif c in '}])':
            assert stack and stack.pop()==dict(zip('}])','{[('))[c]
        i+=1
    assert not stack and quote is None

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--original',required=True,type=Path);args=p.parse_args()
    m=json.loads((ROOT/'patch/manifest.json').read_text());b=args.original.read_bytes()
    assert sha(b)==m['original_sha256'] and len(b)==m['original_size']
    block=(ROOT/'patch/NaviPanel.resource-block.bin').read_bytes(); o=m['record_offset']; n=m['original_record_size']
    assert sha(block)==m['block_sha256'] and len(block)==n
    new=b[:o]+block+b[o+n:]
    assert sha(new)==m['candidate_sha256'] and len(b)==len(new)
    assert b[:o]==new[:o] and b[o+n:]==new[o+n:]
    oldres=resource_map(b);newres=resource_map(new)
    assert len(oldres)==400 and oldres.keys()==newres.keys()
    changed=[k for k in oldres if oldres[k]!=newres[k]]
    assert changed==['/NaviPanel.qml']
    assert newres['/NaviPanel.qml']==(ROOT/'patch/NaviPanel.embedded.qml').read_bytes()
    # ELF32 LE file-header, program headers and executable sections unchanged.
    assert b[:52]==new[:52]
    phoff=struct.unpack_from('<I',b,28)[0]; phentsize,phnum=struct.unpack_from('<HH',b,42)
    assert b[phoff:phoff+phentsize*phnum]==new[phoff:phoff+phentsize*phnum]
    shoff=struct.unpack_from('<I',b,32)[0];shentsize,shnum=struct.unpack_from('<HH',b,46)
    executable=[]
    for i in range(shnum):
        h=struct.unpack_from('<10I',b,shoff+shentsize*i)
        if h[2]&4:
            off,size=h[4:6];assert b[off:off+size]==new[off:off+size];executable.append(i)
    # Exact original models, before the final appended element, unchanged.
    def models(text):
        return [re.findall(r'ListElement\s*\{[^}]*\}',x) for x in re.findall(r'ListModel\s*\{(.*?)(?=\n\s*\}\s*\n)',text,re.S)]
    oldmodels=models(oldres['/NaviPanel.qml'].decode());newmodels=models(newres['/NaviPanel.qml'].decode())
    assert [len(x) for x in oldmodels]==[7,6] and [len(x) for x in newmodels]==[8,7]
    for a,c in zip(oldmodels,newmodels):assert a==c[:-1] and '工具箱' in c[-1]
    checked=[]
    for q in list((ROOT/'examples/device').glob('*.qml'))+[ROOT/'patch/NaviPanel.embedded.qml']:
        lexical_balance(q.read_text());checked.append(q.name)
    tool=ROOT/'tools/rebuild_resource_block.py'
    with tempfile.TemporaryDirectory() as tmp:
        out=Path(tmp)/'candidate';base=[sys.executable,str(tool),'--original',str(args.original),'--qml',str(ROOT/'patch/NaviPanel.embedded.qml'),'--out',str(out)]
        r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==0,r.stderr
        assert sha((out/'Z03.menu-candidate').read_bytes())==m['candidate_sha256']
        r=subprocess.run(base,capture_output=True,text=True);assert r.returncode!=0 and 'exists' in r.stderr
        wrong=Path(tmp)/'wrong';wrong.write_bytes(b'not original')
        r=subprocess.run([sys.executable,str(tool),'--original',str(wrong),'--qml',str(ROOT/'patch/NaviPanel.embedded.qml'),'--out',str(Path(tmp)/'bad')],capture_output=True,text=True)
        assert r.returncode!=0 and not (Path(tmp)/'bad').exists()
        # Low-compressibility valid UTF-8 text must not spill into the next resource.
        longfile=Path(tmp)/'oversized.qml'; longfile.write_text('Item {\n'+ '\n'.join('//'+hashlib.sha256(str(i).encode()).hexdigest() for i in range(200))+'\n}')
        r=subprocess.run([sys.executable,str(tool),'--original',str(args.original),'--qml',str(longfile),'--out',str(Path(tmp)/'oversize')],capture_output=True,text=True)
        assert r.returncode!=0 and 'slot allows' in r.stderr and not (Path(tmp)/'oversize').exists()
    result=dict(status='PASS_OFFLINE_ONLY',original_size=len(b),original_sha256=sha(b),candidate_sha256=sha(new),resource_count=len(oldres),changed_resources=changed,unchanged_resources=len(oldres)-len(changed),outside_resource_record_unchanged=True,elf_file_and_program_headers_unchanged=True,executable_sections_unchanged=executable,menu_counts_before=[7,6],menu_counts_after=[8,7],original_menu_items_and_order_unchanged=True,lexical_checks=checked,python_builder_roundtrip=True,wrong_version_rejected=True,overwrite_rejected=True,oversize_rejected=True,original_unchanged=sha(args.original.read_bytes())==m['original_sha256'],qml_engine_compilation_tested=False,windows_powershell_builder_executed=False,p011_runtime_tested=False)
    (ROOT/'tests/offline-validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
