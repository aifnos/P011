"""Explicit new GUI trial sharing an immutable, completed owned payload via hardlinks."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from audit_device import Adb, SNAPSHOT, WORKSPACE, archive
import gui_trial as G


LINK = r'''
area();directory(REMOTE);directory(REMOTE+'/control');directory(REMOTE+'/payload')
if stat.S_IMODE(os.lstat(REMOTE+'/payload').st_mode)!=0o700:raise ValueError('New staging is not private')
directory(SOURCE);directory(SOURCE+'/payload');directory(SOURCE+'/control')
regular(SOURCE+'/control/COMPLETE',0o600)
old=read_literal(SOURCE+'/control/result.literal')
if not old.get('cleanup_verified') or old.get('remaining_private_processes')!=[] or not old.get('stock_identity_unchanged'):raise ValueError('Source trial was not closed')
for name,binding in BINDINGS.items():
 p=REMOTE+'/control/'+name;s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_size!=binding['bytes']:raise ValueError('New control metadata differs')
 with open(p,'rb') as f:
  if hashlib.sha256(f.read()).hexdigest()!=binding['sha256']:raise ValueError('New control hash differs')
with open(REMOTE+'/control/config.literal','r') as f:config=ast.literal_eval(f.read(262144))
source_config=read_literal(SOURCE+'/control/config.literal')
if source_config['manifest']!=config['manifest']:raise ValueError('Source complete payload identity differs')
if anchor(snapshot())!=config['expected'] or anchor(old['after'])!=config['expected']:raise ValueError('Current or original boot/core identity differs')
for row in config['manifest']['files']:
 p=SOURCE+'/payload/'+row['path'];s=regular(p)
 if s.st_size!=row['bytes'] or stat.S_IMODE(s.st_mode)!=row['mode']:raise ValueError('Source payload metadata differs')
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   b=f.read(262144)
   if not b:break
   h.update(b)
 if h.hexdigest()!=row['sha256']:raise ValueError('Source payload hash differs')
for row in config['manifest']['files']:
 destination=REMOTE+'/payload/'+row['path'];parent=os.path.dirname(destination)
 if not os.path.exists(parent):os.makedirs(parent,0o755)
 directory(parent)
 os.link(SOURCE+'/payload/'+row['path'],destination)
print('RESULT='+repr({'hardlinked_files':len(config['manifest']['files']),'reused_bytes':config['manifest']['bytes'],'payload_bytes_copied':0}))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--transport', required=True, type=int)
    p.add_argument('--from-run', required=True, type=Path)
    p.add_argument('--payload', required=True, type=Path)
    p.add_argument('--expected-snapshot', required=True, type=Path)
    p.add_argument('--uid', type=int, default=65534)
    p.add_argument('--gid', type=int, required=True)
    args = p.parse_args()
    saved = args.from_run.resolve()
    if not saved.is_relative_to((WORKSPACE / 'logs').resolve()):
        raise ValueError('Source GUI run must be in workspace logs')
    oldstate = json.loads((saved / 'state.json').read_text())
    if not G.REMOTE_PATTERN.fullmatch(oldstate['remote']):
        raise ValueError('Invalid source path')
    expected = json.loads(args.expected_snapshot.read_text())
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d-%H%M%S-%f')
    out = WORKSPACE / 'logs' / ('BrowserP011-GUI-Reuse-' + stamp)
    out.mkdir()
    print('LOG_DIR=' + str(out), flush=True)
    result = {'scope': 'DEVICE_QT_GUI_WAYLAND_GLES_ONLY', 'passed': False}
    adb = Adb(args.transport, out)
    try:
        manifest, state = G.prepare_only(args.payload, out, expected, args.transport, args.uid, args.gid)
        if manifest != json.loads((saved / 'manifest.json').read_text()):
            raise ValueError('Local source differs from original complete GUI upload')
        state.update(payload_origin_log=str(saved), payload_origin_remote=oldstate['remote'], payload_reused_by_hardlink=True)
        (out / 'state.json').write_text(json.dumps(state, indent=2))
        bindings = {name: {'bytes': (out / name).stat().st_size, 'sha256': hashlib.sha256((out / name).read_bytes()).hexdigest()}
                    for name in ('config.literal', 'guardian.py')}
        remote = state['remote']
        before, _ = adb.python('before', SNAPSHOT)
        if G.anchor(before) != state['expected'] or any(row['exe'].startswith(G.AREA + '/') for row in before['processes']):
            raise ValueError('Current identity differs or a trial is still running')
        (out / 'before.json').write_text(json.dumps(before, indent=2))
        prefix = G.DEVICE_COMMON + 'REMOTE=' + repr(remote) + '\n'
        scripts = [prefix + 'EXPECTED=' + repr(state['expected']) + '\nPAYLOAD_BYTES=' + repr(manifest['bytes']) + '\n' + G.PREPARE,
                   prefix + 'SOURCE=' + repr(oldstate['remote']) + '\nBINDINGS=' + repr(bindings) + '\n' + LINK,
                   prefix + 'CONTROL_BINDINGS=' + repr(bindings) + '\n' + G.STAGING_VERIFY,
                   prefix + G.VERIFY_START]
        for script in scripts:
            G.remote_command(script)
        adb.python('new-owned-gui-staging', scripts[0])
        for name in ('config.literal', 'guardian.py'):
            adb.run('push-' + name, ['push', str(out / name), remote + '/control/' + name])
        reused, _ = adb.python('verify-and-link-complete-payload', scripts[1])
        adb.python('verify-staging-modes', scripts[2])
        adb.python('launch-fixed-gui', scripts[3])
        result = G.collect(adb, state, 25)
        result.update(payload_reuse=reused, payload_origin_log=str(saved))
    except Exception as exc:
        result.update(error=type(exc).__name__ + ': ' + str(exc), passed=False)
        try:
            after, _ = adb.python('failure-after', SNAPSHOT)
            result['stock_identity_unchanged'] = G.anchor(after) == G.anchor(expected)
            (out / 'failure-after.json').write_text(json.dumps(after, indent=2))
        except Exception as failure:
            result['failure_snapshot_error'] = type(failure).__name__
    finally:
        (out / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        target, checksum = archive(out)
        print(json.dumps({k: v for k, v in result.items() if k != 'device'}))
        print('RESULT_ZIP=' + str(target)); print('ZIP_SHA256=' + checksum)
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
