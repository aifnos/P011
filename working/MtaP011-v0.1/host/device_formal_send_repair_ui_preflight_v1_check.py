"""Private sender preflight after-return carrier. Default PC SOURCE only.

Purely derives the frozen repair UI HOST and its exact existing smoke. The
new fragment runs only after worker.run_fixed/finally returned; it borrows
retained caches and prints only to the already-private carrier stdout.
No actor/clock/IO/close/status/check/finish call or business change is added.
Only CONTROL_NAME and its required Guardian source pin are mechanically
changed in in-memory Worker/Guardian bytes, keeping every method identical.
Original 17 RESULT fields, FAIL/PASS, caps, stock checks and sealer remain.
This file never rewrites frozen sources, outputs, prior FAIL or PASS evidence.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_repair_ui_preflight_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_REPAIR_UI_PREFLIGHT_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_UI_PREFLIGHT_V1_SOURCE_CHECK.cmd'
REPAIR = ('host/device_formal_send_repair_ui_v1_check.py', 13163,
          '3efc100b3a91fa5b6cdf9dc3f51a9c545d3fbc1a885d0c3ab288823997dc390c')
PROJECTION = ('host/send_ui_preflight_after_return_v1.py', 16968,
              'e36727aecfa11a9af397dee3142a2b9d2194468cc22afe48896f198a1870414f')
PARENT = ('candidate/go-observer-libc-v1/runtime/mta_go_readonly_parent.py', 52881,
          'a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6')
ENTRY = ('candidate/go-observer-libc-v1/runtime/mta_go_readonly_entry.py', 45310,
         'b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa')
OWNER = ('candidate/formal-send-filecenter-deploy-v6/runtime/mta_client_service_owner.py', 89599,
         'f8f2bca88915d372ba685024bf995e9d746491559d5c981e83ff1a1e3d6ddea0')
PACKET = ('candidate/go-send-terminal-channel-v94/runtime/mta_observer_packet.py', 48253,
          '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f')
SERVICE = ('candidate/formal-send-filecenter-deploy-v6/runtime/mta_service.py', 145733,
           '38039da81606508f4633662b3802b2882d851df223f32bcf7bd237ee1a53fa76')
FILES = ('runtime/mta_files.py', 10267,
         'c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae')
EXTRA_INPUTS = (REPAIR, PROJECTION, PARENT, ENTRY, OWNER, PACKET, SERVICE, FILES)
OLD_SUFFIX = '-formal-send-picker-package-v1'
CONTROL_SUFFIX = '-formal-send-repair-ui-preflight-v1'
FUNCTION = '_private_send_ui_preflight_after_return_v1'
ANCHOR = (b'component=worker.run_fixed(sources["outer"],sources["guardian"],tuple(fc),'
          b'sources["assets"],smoke_only=True)\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(raw, pin):
    need(type(raw) is bytes and (len(raw), digest(raw)) == pin[1:], 'preflight_source_pin')
    return raw


def parse(raw):
    return ast.parse(raw, feature_version=(3, 5))


def literal(raw, name):
    rows = [row.value for row in parse(raw).body if isinstance(row, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
    need(len(rows) == 1, 'preflight_single_literal')
    return ast.literal_eval(rows[0])


def definitions(raw):
    return {row.name: ast.dump(row, include_attributes=False) for row in parse(raw).body
            if isinstance(row, (ast.FunctionDef, ast.ClassDef))}


def edits(raw, changes):
    current = raw
    for before, after, count in changes:
        need(type(before) is bytes and type(after) is bytes and before != after and
             current.count(before) == count, 'preflight_edit_count')
        current = current.replace(before, after)
    inverse = current
    for before, after, count in reversed(changes):
        need(inverse.count(after) == count, 'preflight_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == raw and definitions(inverse) == definitions(raw), 'preflight_complete_inverse')
    return current


def fragment(raw):
    value = literal(pinned(raw, PROJECTION), 'TARGET_FRAGMENT')
    need(type(value) is bytes and len(value) <= 16384 and value.isascii() and
         max(map(len, value.splitlines())) <= 2048, 'preflight_fragment_budget')
    tree = parse(value)
    need(len(tree.body) == 2 and isinstance(tree.body[0], ast.FunctionDef) and
         tree.body[0].name == FUNCTION and isinstance(tree.body[1], ast.Try), 'preflight_fragment_shape')
    calls = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
             isinstance(row.func, ast.Name) and row.func.id == FUNCTION]
    need(len(calls) == 1 and len(calls[0].args) == 2 and not calls[0].keywords and
         [row.id for row in calls[0].args if isinstance(row, ast.Name)] == ['worker','component'],
         'preflight_after_return_call')
    forbidden = frozenset(('open','close','closed','status','check','collect','finish','read',
        'write','fileno','fstat','stat','lstat','poll','wait','pid','_now','clock','monotonic',
        '_context','_process_current','_closed_facts','_directory_inventory_closed'))
    need(not any(isinstance(row, (ast.Import, ast.ImportFrom)) for row in ast.walk(tree)) and
         not any(isinstance(row, ast.Call) and
             ((isinstance(row.func, ast.Name) and row.func.id in forbidden) or
              (isinstance(row.func, ast.Attribute) and row.func.attr in forbidden))
             for row in ast.walk(tree)), 'preflight_no_active_calls')
    return value


def derived_runtime(inputs, repair):
    """Only fresh CONTROL and its required Guardian pin; complete byte/AST inverse."""
    old_guardian = pinned(inputs[repair.GUARDIAN[0]], repair.GUARDIAN)
    old_worker = pinned(inputs[repair.WORKER[0]], repair.WORKER)
    control_before = ("CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(OLD_SUFFIX) + '\n').encode('ascii')
    control_after = ("CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_SUFFIX) + '\n').encode('ascii')
    guardian = edits(old_guardian, ((control_before, control_after, 1),))
    gp = (len(guardian), digest(guardian))
    before = ('GUARDIAN_PIN = ' + repr(repair.GUARDIAN[1:]) + '\n').encode('ascii')
    after = ('GUARDIAN_PIN = ' + repr(gp) + '\n').encode('ascii')
    worker = edits(old_worker, ((control_before, control_after, 1), (before, after, 1)))
    for old, new, names in ((old_guardian,guardian,{'CONTROL_NAME'}),
                            (old_worker,worker,{'CONTROL_NAME','GUARDIAN_PIN'})):
        left, right = parse(old).body, parse(new).body
        need(len(left) == len(right) and definitions(old) == definitions(new), 'preflight_runtime_methods_same')
        changed = set()
        for a,b in zip(left,right):
            if ast.dump(a,include_attributes=False) == ast.dump(b,include_attributes=False): continue
            need(isinstance(a,ast.Assign) and isinstance(b,ast.Assign) and
                 ast.dump(a.targets[0]) == ast.dump(b.targets[0]) and
                 len(a.targets) == 1 and isinstance(a.targets[0],ast.Name) and
                 a.targets[0].id in names, 'preflight_runtime_only_constants')
            changed.add(a.targets[0].id)
        need(changed == names, 'preflight_runtime_constant_inventory')
    need(literal(worker,'GUARDIAN_PIN') == gp and literal(worker,'SESSION') == repair.SESSION and
         literal(guardian,'SESSION') == repair.SESSION, 'preflight_control_pin_closed')
    return worker, guardian


def ui_program(inputs, fc_rows, repair, original, encoder):
    """Original program plus two actual-source encodings and one post-return fragment."""
    program, wire = original(inputs, fc_rows)
    worker, guardian = derived_runtime(inputs, repair)
    changes = []
    for key,pin,current in (('worker',repair.WORKER,worker), ('guardian',repair.GUARDIAN,guardian)):
        def encoded_source(raw, actual_pin):
            return ('sources['+repr(key)+']=decode((\n'+encoder(raw)+'),'+
                    repr(actual_pin[0])+','+repr(actual_pin[1])+')').encode('ascii')
        changes.append((encoded_source(inputs[pin[0]],pin[1:]),
                        encoded_source(current,(len(current),digest(current))),1))
    value = fragment(inputs[PROJECTION[0]])
    need(program.count(ANCHOR) == 1 and program.count(b'print("RESULT="+repr(component))') == 1 and
         program.index(ANCHOR) < program.index(b'print("RESULT="+repr(component))'), 'preflight_original_return_anchor')
    changes.append((ANCHOR, ANCHOR+value,1))
    changed = edits(program,changes)
    need(changed.count(ANCHOR+value) == 1 and
         changed.index(ANCHOR+value) < changed.index(b'print("RESULT="+repr(component))'), 'preflight_only_after_return')
    old_tree, new_tree = parse(program), parse(changed)
    # Reversing every complete bytes edit restores every original AST node,
    # including component/closed/alarm/SystemExit; none is reconstructed.
    inverse = changed.replace(ANCHOR+value,ANCHOR,1)
    for before,after,count in reversed(changes[:-1]): inverse = inverse.replace(after,before,count)
    need(inverse == program and ast.dump(parse(inverse),include_attributes=False) ==
         ast.dump(old_tree,include_attributes=False), 'preflight_program_ast_inverse')
    need(not any(isinstance(row,ast.ImportFrom) for row in new_tree.body), 'preflight_no_new_imports')
    return changed, wire


def prepare():
    """Pure definitions only. No prior main/test, device, RF or file writes."""
    repair_raw = pinned((BASE/REPAIR[0]).read_bytes(),REPAIR)
    repair = types.ModuleType('fixed_repair_ui_preflight_origin_definitions')
    repair.__file__ = str(BASE/REPAIR[0])
    exec(compile(repair_raw,repair.__file__,'exec'),repair.__dict__)
    original_module, origin = repair.prepare()
    original_program = original_module.ui_program
    changes = []
    for name,value in (('SELF',SELF),('CMD',CMD),('SOURCE_BASELINES',repair.SOURCE_BASELINES+EXTRA_INPUTS)):
        rows = [row for row in parse(origin).body if isinstance(row,ast.Assign) and
                any(isinstance(target,ast.Name) and target.id == name for target in row.targets)]
        need(len(rows) == 1,'preflight_host_assignment')
        row = rows[0]
        changes.append((b''.join(origin.splitlines(True)[row.lineno-1:row.end_lineno]),
                        (name+' = '+repr(value)+'\n').encode('ascii'),1))
    for name,body in (('ui_program',b'def ui_program(inputs,fc_rows):\n    return _PREFLIGHT_UI_PROGRAM(inputs,fc_rows)\n'),
                      ('diagnostic_source_boundary',b'def diagnostic_source_boundary(inputs):\n    return _PREFLIGHT_SOURCE_BOUNDARY(inputs)\n')):
        row = next(row for row in parse(origin).body if isinstance(row,ast.FunctionDef) and row.name == name)
        changes.append((b''.join(origin.splitlines(True)[row.lineno-1:row.end_lineno]),body,1))
    changes.extend(((('for path in (SELF,CMD,CONTRACT,'+repr(repair.SOURCE_CMD)+'):').encode('ascii'),
                     ('for path in (SELF,CMD,CONTRACT,'+repr(SOURCE_CMD)+'):').encode('ascii'),1),
                    (b"('formal-send-repair-ui-v1-'+mode+",b"('formal-send-repair-ui-preflight-v1-'+mode+",1),
                    (("+SESSION+'"+OLD_SUFFIX+"'").encode('ascii'),
                     ("+SESSION+'"+CONTROL_SUFFIX+"'").encode('ascii'),1)))
    current = edits(origin,changes)
    a,b = definitions(origin),definitions(current)
    need(set(a) == set(b) and {name for name in a if a[name] != b[name]} ==
         {'ui_program','diagnostic_source_boundary','main'}, 'preflight_host_definition_scope')
    left,right = parse(origin).body,parse(current).body
    need(len(left) == len(right),'preflight_host_toplevel_count')
    changed_assignments = set()
    for x,y in zip(left,right):
        if ast.dump(x,include_attributes=False) == ast.dump(y,include_attributes=False): continue
        if isinstance(x,ast.FunctionDef) and isinstance(y,ast.FunctionDef):
            need(x.name == y.name and x.name in ('ui_program','diagnostic_source_boundary','main'),
                 'preflight_host_function_scope')
        else:
            need(isinstance(x,ast.Assign) and isinstance(y,ast.Assign) and len(x.targets) == 1 and
                 isinstance(x.targets[0],ast.Name) and ast.dump(x.targets[0]) == ast.dump(y.targets[0]) and
                 x.targets[0].id in ('SELF','CMD','SOURCE_BASELINES'), 'preflight_host_other_scope')
            changed_assignments.add(x.targets[0].id)
    need(changed_assignments == {'SELF','CMD','SOURCE_BASELINES'},'preflight_host_assignment_inventory')
    module = types.ModuleType('fixed_formal_send_repair_ui_preflight_v1_host')
    module.__file__ = str(BASE/repair.MOTHER[0])
    exec(compile(current,'<derived-send-ui-preflight-v1-host>','exec'),module.__dict__)
    def boundary(inputs):
        need(repair.repair_source_boundary(inputs) is True,'preflight_original_repair_boundary')
        for pin in EXTRA_INPUTS: pinned(inputs[pin[0]],pin)
        fragment(inputs[PROJECTION[0]])
        derived_runtime(inputs,repair)
        parent = inputs[PARENT[0]]
        need(b"if returned != 0: _fail('parent_child_failed')" in parent and
             b'except BaseException: return 1  # Failure/partial inventory stays original and private.' in inputs[ENTRY[0]] and
             b"if self.send_preflight_ticket is not None and (self.send_preflight_ticket['unknown'] is not False or" in inputs[OWNER[0]],
             'preflight_actual_refusal_source')
        return True
    module._PREFLIGHT_SOURCE_BOUNDARY = boundary
    module._PREFLIGHT_UI_PROGRAM = lambda inputs,fc_rows: ui_program(
        inputs,fc_rows,repair,original_program,original_module.encoded)
    return module,current


def main():
    module,raw = prepare()
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())
