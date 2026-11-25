#!/usr/bin/env python3
"""Offline firmware/resource checks. Never opens USB or executes target code.
Usage: python validate_offline.py --original PATH_TO_ORIGINAL_Z03
"""
import argparse, hashlib, importlib.util, json, re, shutil, struct, subprocess, sys, tempfile, zlib
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
        # The existing BrowserPage contains escaped-slash regex literals. Do not
        # mistake /https?:\/\// for a line comment or brackets inside regex classes.
        prefix=text[:i].rstrip()
        if c=='/' and (not prefix or prefix[-1] in '=(:,[!&|?{;' or re.search(r'\b(return|throw|case|typeof|void|delete|in|instanceof)$',prefix)):
            i+=1;in_class=False
            while i<len(text):
                c=text[i]
                if c=='\\':i+=2;continue
                assert c not in '\r\n','Unclosed regex literal'
                if c=='[':in_class=True
                elif c==']':in_class=False
                elif c=='/' and not in_class:break
                i+=1
            assert i<len(text),'Unclosed regex literal'
            i+=1
            while i<len(text) and text[i].isalpha():i+=1
            continue
        if c in '{[(':stack.append(c)
        elif c in '}])':
            assert stack and stack.pop()==dict(zip('}])','{[('))[c]
        i+=1
    assert not stack and quote is None

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--original',required=True,type=Path);args=p.parse_args()
    m=json.loads((ROOT/'patch/manifest.json').read_text(encoding='utf-8'));b=args.original.read_bytes()
    builder_path=ROOT/'tools/rebuild_bluetooth_resource.py'
    spec=importlib.util.spec_from_file_location('bt_resource_builder',builder_path)
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    builder.validate_manifest_ranges(m)
    assert sha(b)==builder.EXPECTED==m['original_sha256'] and len(b)==builder.ORIGINAL_SIZE==m['original_size']
    dual='bluetooth_patch' in m
    patches=[(m,0x1c625c,1584,'NaviPanel','/NaviPanel.qml')]
    if dual:patches.append((m['bluetooth_patch'],0x21e225,3992,'SetBtPage',builder.BT_PATH))
    new=bytearray(b);last_end=0
    for meta,o,n,filename,path in patches:
        assert o>=last_end and o+n<=len(b)
        assert struct.unpack_from('>I',b,o)[0]==n-4
        block=(ROOT/('patch/'+filename+'.resource-block.bin')).read_bytes()
        qml=(ROOT/('patch/'+filename+'.embedded.qml')).read_bytes()
        assert sha(block)==meta['block_sha256'] and len(block)==n
        assert sha(qml)==meta['embedded_qml_sha256'] and builder.decode_block(block,n)==qml
        new[o:o+n]=block;last_end=o+n
    new=bytes(new)
    assert sha(new)==m['candidate_sha256'] and len(b)==len(new)
    cursor=0
    for meta,o,n,filename,path in patches:
        assert b[cursor:o]==new[cursor:o];cursor=o+n
    assert b[cursor:]==new[cursor:]
    oldres=resource_map(b);newres=resource_map(new)
    assert len(oldres)==400 and oldres.keys()==newres.keys()
    changed=[k for k in oldres if oldres[k]!=newres[k]]
    assert set(changed)==set(x[4] for x in patches)
    assert m['other_resources_unchanged']==400-len(patches)
    assert set(m['changed_resources'])==set(changed)
    for meta,o,n,filename,path in patches:
        assert newres[path]==(ROOT/('patch/'+filename+'.embedded.qml')).read_bytes()
        assert sha(oldres[path])==meta['original_qml_sha256']
    # ELF32 LE file-header, program headers and executable sections unchanged.
    assert b[:52]==new[:52]
    phoff=struct.unpack_from('<I',b,28)[0]; phentsize,phnum=struct.unpack_from('<HH',b,42)
    assert b[phoff:phoff+phentsize*phnum]==new[phoff:phoff+phentsize*phnum]
    shoff=struct.unpack_from('<I',b,32)[0];shentsize,shnum=struct.unpack_from('<HH',b,46)
    assert b[shoff:shoff+shentsize*shnum]==new[shoff:shoff+shentsize*shnum]
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
    for q in list((ROOT/'examples/device').glob('*.qml'))+[ROOT/('patch/'+x[3]+'.embedded.qml') for x in patches]:
        try:lexical_balance(q.read_text(encoding='utf-8'))
        except AssertionError as error:raise AssertionError('QML lexical check failed: '+str(q)) from error
        checked.append(q.name)
    # Line-edge trimming must preserve multiline strings/templates and comments.
    fixture='  Item {  \n  property string a: " keep  "  \n  /* keep  \n    middle  \n  end */  \n  property var b: ` first  \n  second `  \n  // keep comment  \n  }  \n'
    trimmed=builder.trim_external_whitespace(fixture)
    assert '" keep  "' in trimmed and '/* keep  \n    middle  \n  end */' in trimmed
    assert '` first  \n  second `' in trimmed and '// keep comment  \n' in trimmed
    assert trimmed.startswith('Item {\n') and trimmed.endswith('}\n')
    nav_block=(ROOT/'patch/NaviPanel.resource-block.bin').read_bytes()
    nav_only=b[:0x1c625c]+nav_block+b[0x1c625c+1584:]
    powershell_tested=False
    tool=ROOT/'tools/rebuild_resource_block.py'
    with tempfile.TemporaryDirectory() as tmp:
        out=Path(tmp)/'candidate';base=[sys.executable,str(tool),'--original',str(args.original),'--qml',str(ROOT/'patch/NaviPanel.embedded.qml'),'--out',str(out)]
        r=subprocess.run(base,capture_output=True,text=True);assert r.returncode==0,r.stderr
        assert sha((out/'Z03.menu-candidate').read_bytes())==sha(nav_only)
        r=subprocess.run(base,capture_output=True,text=True);assert r.returncode!=0 and 'exists' in r.stderr
        wrong=Path(tmp)/'wrong';wrong.write_bytes(b'not original')
        r=subprocess.run([sys.executable,str(tool),'--original',str(wrong),'--qml',str(ROOT/'patch/NaviPanel.embedded.qml'),'--out',str(Path(tmp)/'bad')],capture_output=True,text=True)
        assert r.returncode!=0 and not (Path(tmp)/'bad').exists()
        # Low-compressibility valid UTF-8 text must not spill into the next resource.
        longfile=Path(tmp)/'oversized.qml'; longfile.write_text('Item {\n'+ '\n'.join('//'+hashlib.sha256(str(i).encode()).hexdigest() for i in range(200))+'\n}')
        r=subprocess.run([sys.executable,str(tool),'--original',str(args.original),'--qml',str(longfile),'--out',str(Path(tmp)/'oversize')],capture_output=True,text=True)
        assert r.returncode!=0 and 'slot allows' in r.stderr and not (Path(tmp)/'oversize').exists()
        if dual:
            dualout=Path(tmp)/'dual'
            dualbase=[sys.executable,str(builder_path),'--original',str(args.original),'--package-dir',str(ROOT),'--out',str(dualout)]
            r=subprocess.run(dualbase,capture_output=True,text=True);assert r.returncode==0,r.stderr
            assert sha((dualout/'Z03.menu-candidate').read_bytes())==m['candidate_sha256']
            assert (dualout/'SetBtPage.resource-block.bin').read_bytes()==(ROOT/builder.BT_BLOCK_FILE).read_bytes()
            r=subprocess.run(dualbase,capture_output=True,text=True);assert r.returncode!=0 and 'exists' in r.stderr
            wrongout=Path(tmp)/'dual-wrong'
            r=subprocess.run([sys.executable,str(builder_path),'--original',str(wrong),'--package-dir',str(ROOT),'--out',str(wrongout)],capture_output=True,text=True)
            assert r.returncode!=0 and not wrongout.exists()
            fixturepkg=Path(tmp)/'fixture-package';shutil.copytree(ROOT/'patch',fixturepkg/'patch')
            def reject(label,manifest=None,readable=None,error=None):
                (fixturepkg/'patch/manifest.json').write_text(json.dumps(m if manifest is None else manifest),encoding='utf-8')
                (fixturepkg/'patch/SetBtPage.readable.qml').write_text((ROOT/'patch/SetBtPage.readable.qml').read_text(encoding='utf-8') if readable is None else readable,encoding='utf-8')
                dest=Path(tmp)/label
                result=subprocess.run([sys.executable,str(builder_path),'--original',str(args.original),'--package-dir',str(fixturepkg),'--out',str(dest)],capture_output=True,text=True)
                assert result.returncode!=0 and not dest.exists(),(label,result.stdout,result.stderr)
                if error:assert error in result.stderr,result.stderr
            bad=json.loads(json.dumps(m));bad['bluetooth_patch']['record_offset']=0x1c625c
            reject('overlap',manifest=bad,error='fixed slot/path')
            bad=json.loads(json.dumps(m));bad['bluetooth_patch']['embedded_qml_file']='../arbitrary.qml'
            reject('path',manifest=bad,error='fixed slot/path')
            bad=json.loads(json.dumps(m));bad['original_sha256']='0'*64
            reject('manifest-pin',manifest=bad,error='pinned original')
            oversized='Item {\n'+'\n'.join('//'+hashlib.sha256(str(i).encode()).hexdigest() for i in range(400))+'\n}'
            reject('dual-oversize',readable=oversized,error='slot allows')
            # Rebuild from a legacy single-patch manifest remains supported.
            legacy=json.loads(json.dumps(m));legacy.pop('bluetooth_patch');legacy['candidate_sha256']=sha(nav_only)
            legacy['changed_resources']=['/NaviPanel.qml'];legacy['other_resources_unchanged']=399
            (fixturepkg/'patch/manifest.json').write_text(json.dumps(legacy),encoding='utf-8')
            (fixturepkg/'patch/SetBtPage.readable.qml').write_bytes((ROOT/'patch/SetBtPage.readable.qml').read_bytes())
            r=subprocess.run([sys.executable,str(builder_path),'--original',str(args.original),'--package-dir',str(fixturepkg),'--out',str(Path(tmp)/'legacy-upgrade')],capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert sha((Path(tmp)/'legacy-upgrade/Z03.menu-candidate').read_bytes())==sha(new)
        powershell=shutil.which('powershell.exe') or shutil.which('pwsh')
        if powershell:
            def psquote(value):return "'"+str(value).replace("'","''")+"'"
            psroot=Path(tmp)/'powershell-builds'
            script="""
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$PackageDir=PACKAGE
$original=ORIGINAL
$work=WORK
& (Join-Path $PackageDir 'tools/Build-MenuCandidate.ps1') -PackageDir $PackageDir -OriginalPath $original -WorkRoot $work
if(-not $?){throw 'Standalone builder failed'}
$standalone=@(Get-ChildItem -LiteralPath (Join-Path $work 'MenuLab/build') -Filter 'Z03.menu-candidate' -Recurse)
if($standalone.Count -ne 1){throw 'Expected one standalone candidate'}
$parseTokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PackageDir 'P011-MenuTest.ps1'),[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Run script has parse errors'}
foreach($functionName in @('Bytes-Hash','Build-Candidate')){
    $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName},$true))
    if($definition.Count -ne 1){throw 'Function extraction ambiguous'}
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
function Log-Line([string]$Value){Write-Host $Value}
$runDestination=Join-Path $work 'run-function-candidate'
Build-Candidate -Original $original -Destination $runDestination
$expected=(Get-Content -LiteralPath (Join-Path $PackageDir 'patch/manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json).candidate_sha256
$first=(Get-FileHash -LiteralPath $standalone[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$second=(Get-FileHash -LiteralPath $runDestination -Algorithm SHA256).Hash.ToLowerInvariant()
if($first -cne $expected -or $second -cne $expected){throw 'PowerShell builders disagree with manifest'}
$overwriteRejected=$false
try{Build-Candidate -Original $original -Destination $runDestination}catch{if($_.Exception.Message -match 'exists'){$overwriteRejected=$true}else{throw}}
if(-not $overwriteRejected){throw 'Run builder overwrote candidate'}
Write-Host ('POWERSHELL_BUILD_TEST_OK:'+$expected)
""".replace('PACKAGE',psquote(ROOT)).replace('ORIGINAL',psquote(args.original.resolve())).replace('WORK',psquote(psroot))
            r=subprocess.run([powershell,'-NoProfile','-ExecutionPolicy','Bypass','-Command',script],capture_output=True,text=True)
            assert r.returncode==0 and 'POWERSHELL_BUILD_TEST_OK:'+sha(new) in r.stdout,(r.stdout,r.stderr)
            powershell_tested=True
    result=dict(status='PASS_OFFLINE_ONLY',original_size=len(b),original_sha256=sha(b),candidate_sha256=sha(new),resource_count=len(oldres),changed_resources=changed,unchanged_resources=len(oldres)-len(changed),outside_resource_record_unchanged=True,elf_file_and_program_headers_unchanged=True,elf_section_headers_unchanged=True,executable_sections_unchanged=executable,menu_counts_before=[7,6],menu_counts_after=[8,7],original_menu_items_and_order_unchanged=True,lexical_checks=checked,python_builder_roundtrip=True,dual_patch_builder_roundtrip=dual,legacy_single_patch_compatible=True,trim_preserves_strings_and_comments=True,fixed_slot_and_path_rejections=dual,wrong_version_rejected=True,overwrite_rejected=True,oversize_rejected=True,original_unchanged=sha(args.original.read_bytes())==m['original_sha256'],qml_engine_compilation_tested=False,windows_powershell_builder_executed=powershell_tested,windows_run_build_function_executed=powershell_tested,powershell_candidates_match_python=powershell_tested,p011_runtime_tested=False)
    (ROOT/'tests/offline-validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
