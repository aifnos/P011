"""New fixed deadline-constructor HOST check; no service or device starts."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/duplex_window_host_check.py'
CMD = 'HOST_MTA_DUPLEX_WINDOW_CHECK.cmd'
PINS = (
    ('candidate/duplex-window-v1/runtime/formal_send_session.py', 24023,
     '154a073f88d50c4c71ec7562f830f4e91a459e7e67508a7e24369611df1964e7'),
    ('candidate/duplex-window-v1/runtime/mta_formal_receive_session.py', 82938,
     'bc176c2d74671dbbddac1dab9cfe5e2567d358b873241342ae5fb169334bd9a1'),
    ('candidate/formal-send-v1/runtime/formal_send_session.py', 21984,
     '290aa340a0aa646563625a2c64297886f11393f6f1e9986920fa9daee63aca19'),
    ('candidate/receive-completed-archive-v1/integrated/runtime/mta_formal_receive_session.py',
     80671, 'dab38234422d0ff41407c46dbaecc7385d05ef06932610eb65f4dce49fd7653b'),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('readback')


def narrow_diff(old, new, class_name, receive):
    before = ast.parse(old, feature_version=(3, 5))
    after = ast.parse(new, feature_version=(3, 5))
    old_body, new_body = list(before.body), list(after.body)
    if receive:
        added = [n for n in new_body if isinstance(n, ast.Import) and
                 len(n.names) == 1 and n.names[0].name == 'math' and n.names[0].asname is None]
        if len(added) != 1: raise ValueError('math_import')
        new_body.remove(added[0])
    if len(old_body) != len(new_body): raise ValueError('topology')
    changed = []
    for a, b in zip(old_body, new_body):
        if isinstance(a, ast.ClassDef) and a.name == class_name:
            if not isinstance(b, ast.ClassDef) or b.name != a.name or len(a.body) != len(b.body):
                raise ValueError('class_shape')
            for x, y in zip(a.body, b.body):
                if ast.dump(x) != ast.dump(y):
                    if not isinstance(x, ast.FunctionDef) or x.name not in ('__init__', 'window_current') or y.name != x.name:
                        raise ValueError('business_method_changed')
                    changed.append(class_name + '.' + x.name)
        elif ast.dump(a) != ast.dump(b):
            if not isinstance(a, ast.FunctionDef) or a.name != 'run_fixed' or b.name != a.name:
                raise ValueError('top_level_changed')
            changed.append('run_fixed')
    if changed != [class_name + '.__init__', class_name + '.window_current', 'run_fixed']:
        raise ValueError('narrow_diff')
    return changed


CHILD = r'''
import hashlib,pathlib,sys,time
root=pathlib.Path(sys.argv[1])
pins=(
 ('candidate/duplex-window-v1/runtime/formal_send_session.py',24023,'154a073f88d50c4c71ec7562f830f4e91a459e7e67508a7e24369611df1964e7'),
 ('candidate/duplex-window-v1/runtime/mta_formal_receive_session.py',82938,'bc176c2d74671dbbddac1dab9cfe5e2567d358b873241342ae5fb169334bd9a1'))
spaces=[]
for i,(name,size,sha) in enumerate(pins):
 raw=(root/name).read_bytes()
 assert len(raw)==size and hashlib.sha256(raw).hexdigest()==sha
 ns={'__name__':'duplex_window_host_private_'+str(i),'__file__':str(root/name)}
 spaces.append(ns)
 exec(compile(raw,str(root/name),'exec'),ns)
S,R=spaces[0]['FixedSendSession'],spaces[1]['FixedSession']
deadline=float(time.monotonic()+30.0);cleanup=deadline+60.0
senders=[S(deadline,cleanup,True,'send-interactive-v1') for _ in range(2)]
receivers=[R((),False,deadline,cleanup,True,'receive-interactive-v1',True) for _ in range(2)]
for obj in senders+receivers:
 assert obj.until is deadline and obj.parent_until is deadline and obj.cleanup_until==cleanup
 assert obj.window_current() is True and obj.until<=obj.profile_until
 obj.check()
 assert obj.rows==[] and obj.owner is None and obj.boot is None
 assert obj._parent_window_original is obj._parent_window_retained
 assert obj._window_original is obj._window_retained
assert senders[1].window_started_at>=senders[0].window_started_at
assert receivers[1].window_started_at>=receivers[0].window_started_at
print('DUPLEX_WINDOW_CASE=repeated_children_share_original_absolute_deadline')
later=float(time.monotonic()+550.0);later_cleanup=later+60.0
diagnostic=[S(later,later_cleanup),R((),False,later,later_cleanup)]
for obj in diagnostic:
 assert obj.until is obj.profile_until and obj.until==obj.window_started_at+60.0
 assert obj.cleanup_until==obj.until+60.0<=later_cleanup and obj.window_current() is True
 obj.check()
print('DUPLEX_WINDOW_CASE=diagnostic_profile_remains_shorter_than_parent')
for ctor in (lambda a,b:S(a,b,True,'send-interactive-v1'),
             lambda a,b:R((),False,a,b,True,'receive-interactive-v1',True)):
 past=float(time.monotonic()-1.0)
 for a,b in ((True,61.0),(float('nan'),float('nan')),(float('inf'),float('inf')),
             (deadline,deadline+59.0),(past,past+60.0)):
  try:ctor(a,b)
  except ValueError:pass
  else:raise AssertionError('invalid_parent_accepted')
 future=float(time.monotonic()+601.0)
 try:ctor(future,future+60.0)
 except ValueError:pass
 else:raise AssertionError('parent_cap_accepted')
print('DUPLEX_WINDOW_CASE=invalid_expired_nonfinite_or_overlong_parent_refused')
for obj in senders+receivers:
 original=obj.parent_until
 obj.parent_until=original+1.0
 assert obj.window_current() is False
 obj.parent_until=original
 assert obj.window_current() is True
 original_tuple=obj._parent_window_original
 obj._parent_window_original=(obj.parent_until,obj.parent_cleanup_until)
 assert obj.window_current() is False
 obj._parent_window_original=original_tuple
 assert obj.window_current() is True
print('DUPLEX_WINDOW_CASE=changed_parent_value_or_original_tuple_refused')
print('DUPLEX_WINDOW_CONTRACTS=4')
'''


def main():
    if sys.argv[1:]: return 2
    out = BASE / 'results' / ('duplex-window-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs, stdout, stderr = {}, b'', b''
    result = dict(schema='p011-duplex-window-host-v1', passed=False, source_inputs=0,
        source_preserved=False, child_exit=None, host_exit=None, remote_exit=None, error=None,
        actual_constructor_clock_thread_pid=False, actual_parent_clipping=False,
        old_methods=0, case_count=0, business_graph=False, service=False, owner=False,
        stage=False, native=False, rf=False, device=False, phone=False,
        send_verified=False, receive_verified=False, restoration_verified=False,
        original_service_roots_unchanged=True, final_ui_integrated=False)
    try:
        for name, size, sha in PINS:
            raw = (BASE / name).read_bytes()
            if len(raw) != size or digest(raw) != sha: raise ValueError('pin')
            inputs[name] = raw
        for name in (SELF, CMD): inputs[name] = (BASE / name).read_bytes()
        for name, raw in inputs.items(): save(out / 'private-inputs' / name, raw)
        inventory = {name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in inputs.items()}
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2)+'\n').encode('ascii'))
        result['source_changes'] = [
            narrow_diff(inputs[PINS[2][0]], inputs[PINS[0][0]], 'FixedSendSession', False),
            narrow_diff(inputs[PINS[3][0]], inputs[PINS[1][0]], 'FixedSession', True)]
        save(out / 'private-child.py', CHILD.encode('ascii'))
        child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-child.py'),
            str(out / 'private-inputs')], input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(out), timeout=15, check=False)
        stdout, stderr = child.stdout, child.stderr
        result['child_exit'] = result['host_exit'] = child.returncode
        result['case_count'] = len([line for line in stdout.splitlines() if line.startswith(b'DUPLEX_WINDOW_CASE=')])
        expected = [b'DUPLEX_WINDOW_CASE=repeated_children_share_original_absolute_deadline',
            b'DUPLEX_WINDOW_CASE=diagnostic_profile_remains_shorter_than_parent',
            b'DUPLEX_WINDOW_CASE=invalid_expired_nonfinite_or_overlong_parent_refused',
            b'DUPLEX_WINDOW_CASE=changed_parent_value_or_original_tuple_refused',
            b'DUPLEX_WINDOW_CONTRACTS=4']
        result['source_preserved'] = all((BASE/name).read_bytes() == raw and
            (out/'private-inputs'/name).read_bytes() == raw for name, raw in inputs.items())
        result['passed'] = (child.returncode == 0 and not stderr and stdout.splitlines() == expected and
                            result['source_preserved'])
        if result['passed']:
            result['actual_constructor_clock_thread_pid'] = True
            result['actual_parent_clipping'] = True
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b'', error.stderr or b''
        result['error'] = 'timeout_child_closure_unknown'
    except Exception as error:
        result['error'] = type(error).__name__
        save(out/'private-error.txt', str(error).encode('utf-8'))
    result['source_inputs'] = len(inputs)
    for name, raw in (('stdout', stdout), ('stderr', stderr)):
        save(out/(name+'.raw'), raw)
        result[name+'_bytes'], result[name+'_sha256'] = len(raw), digest(raw)
    save(out/'child-exit.raw', (str(result['child_exit'])+'\n').encode('ascii'))
    save(out/'host-exit.raw', (str(result['host_exit'])+'\n').encode('ascii'))
    save(out/'remote-exit.raw', b'NOT_RUN_DEVICE\n')
    code = 0 if result['passed'] else 1
    result['checker_exit'] = code
    public = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode('ascii')
    note = (b'New HOST constructor/deadline check only. Full frozen new modules load privately; '
        b'only actual constructors, window_current and check execute with real HOST monotonic, '
        b'thread, PID and empty resource inventories. Four fixed cases cover original parent '
        b'deadline reuse, shorter diagnostic caps, invalid parent refusal and explicit identity '
        b'faults. No mocked clock, IO, RF or Owner. AST diff permits only ctor/window_current/'
        b'run_fixed plus receive math import; other original business methods stay unchanged. '
        b'No run_fixed/start/run/close, source IO, service, Boot/Owner/Native, P011 or phone. '
        b'Not final UI integration, repeated receive acceptance, send or restoration. '
        b'All six inputs and raw logs/exits remain private; this ZIP contains only result and README.\n')
    save(out/'result.json', public); save(out/'README.txt', note)
    save(out/'checker-exit.raw', (str(code)+'\n').encode('ascii'))
    bundle = out/'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public); archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != public or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=result['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
