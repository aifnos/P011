"""Freeze this source candidate and explicitly selected non-private evidence.

PC-only. No build output overwrites, no ADB, no firmware or user-data archive.
"""
import argparse
import hashlib
import json
import pathlib
import zipfile

BASE=pathlib.Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('host-result','device-result','browser-dir','browser-console','report','out'):
        parser.add_argument('--'+name,required=True,type=pathlib.Path)
    args=parser.parse_args()
    host=json.loads((args.host_result/'result.json').read_text(encoding='utf-8'))
    assert host['passed'] and not host['adb_invoked']
    for row in json.loads((args.host_result/'source-manifest.json').read_text(encoding='utf-8')):
        assert hashlib.sha256((BASE/row['path']).read_bytes()).hexdigest()==row['sha256'],'Source changed since host verification: '+row['path']
    device=json.loads((args.device_result/'result.json').read_text())
    status=json.loads((args.device_result/'status.json').read_text())
    assert status['host_exit']==0 and status['remote_exit']==0 and status['cleanup_remote_verified']
    for name in ('stock_hashes_unchanged','stock_processes_unchanged','temporary_files_removed',
                 'no_lan_or_playback_started','authenticated_loopback_http','live_metrics',
                 'user_files_roundtrip','prior_stdin_probe_not_running'):
        assert device[name],name
    assert device['owned_temporary_directory_count']==0
    original=BASE/'tests/fixtures/upload-test.txt'
    downloaded=args.browser_dir/'p011-next-download.txt'
    assert original.read_bytes()==downloaded.read_bytes(),'Browser download mismatch'
    entries={}
    def add(file,name):
        assert file.is_file() and not file.is_symlink(),str(file)
        assert name not in entries
        entries[name]=file.read_bytes()
    for name in ('README.md','INTEGRATION.md','PREVIEW_PC.cmd','VERIFY_HOST.cmd'):
        add(BASE/name,'ToolboxNext-v0.5.0/'+name)
    for folder in ('runtime','device','web','host','tests'):
        for file in sorted((BASE/folder).rglob('*')):
            if file.is_file() and '__pycache__' not in file.parts:
                assert file.suffix.lower() in ('.py','.qml','.js','.html','.css','.svg','.txt','.md'),str(file)
                add(file,'ToolboxNext-v0.5.0/'+file.relative_to(BASE).as_posix())
    source=[{'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(entries.items())]
    source_id=hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest()
    for file in sorted(args.host_result.rglob('*')):
        if file.is_file():add(file,'Evidence/host/'+file.relative_to(args.host_result).as_posix())
    for name in ('result.json','status.json','stdout.raw','stderr.raw','push.stdout.raw','push.stderr.raw','cleanup.stdout.raw','cleanup.stderr.raw'):
        add(args.device_result/name,'Evidence/device/'+name)
    for name in ('p011-next-transfer-desktop.png','p011-next-transfer-mobile.png','p011-next-transfer-duplicate.png','p011-next-download.txt','P011-Next-Browser-QA.md'):
        add(args.browser_dir/name,'Evidence/browser/'+name)
    add(args.browser_console,'Evidence/browser/console.raw')
    add(args.report,'Evidence/verification-report.md')
    manifest={'candidate':'v0.5.0','release_status':'independent candidate; not installed on pen',
              'source_identity_sha256':source_id,
              'files':[{'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(entries.items())]}
    args.out.mkdir(parents=True,exist_ok=True)
    archive=args.out/('P011-ToolboxNext-v0.5.0-CANDIDATE-'+source_id[:12]+'.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name,data in sorted(entries.items()):bundle.writestr(name,data)
        bundle.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2).encode('utf-8'))
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.testzip() is None
        for row in manifest['files']:assert hashlib.sha256(bundle.read(row['path'])).hexdigest()==row['sha256']
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum=archive.with_suffix('.sha256')
    with checksum.open('x',encoding='ascii') as output:output.write(digest+'  '+archive.name+'\n')
    print('CANDIDATE_ZIP='+str(archive));print('SOURCE_ID='+source_id)
    print('ZIP_SHA256='+digest);print('ARCHIVE_FILES='+str(len(entries)+1));print('CRC_AND_EVERY_FILE_HASH=PASS')


if __name__=='__main__':main()
