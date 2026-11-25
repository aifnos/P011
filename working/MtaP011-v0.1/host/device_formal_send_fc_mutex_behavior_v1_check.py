"""Real Owner/no-file mutex behavior diagnostic; default PC SOURCE only.

Reuse the frozen, passed mutex service carrier and actual Parent/Boot/Owner.
The only added DEVICE work is three retained diagnostic threads calling the
unchanged real Companion.media_row with a nonexistent, syntactically valid
capability while the main worker holds the original media table RLock. One
short caller deadline and original Owner close cancellation are observed.
No HTTP, credentials, file open, audio, RF, GUI, phone, Stage or writer call.
Original Parent60+cleanup60/alarm180/HOST210 and every close gate remain.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_fc_mutex_behavior_v1_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FC_MUTEX_BEHAVIOR_V1_CHECK.cmd'
TEST_CMD = 'TEST_MTA_FORMAL_SEND_FC_MUTEX_BEHAVIOR_V1.cmd'
MOTHER = ('host/device_formal_send_fc_mutex_service_v1_check.py', 10584,
          'b49cd447d43fcc07251e68126fb10771d84fe35cd544f4da22a0a59d331853d6')
KIND = 'formal-send-fc-mutex-v1-owner-behavior-diagnostic'
BEHAVIOR_REQUIRED = (
    'actual_owner_media_methods_unchanged', 'actual_media_mutex_original_held',
    'short_media_deadline_wait_observed', 'short_media_deadline_rejected',
    'short_media_waiter_exited_while_held', 'media_mutex_usable_after_short_deadline',
    'owner_close_cancellation_wait_observed', 'owner_close_cancellation_rejected',
    'owner_close_waiter_exited', 'owner_close_waiter_exited_while_held', 'diagnostic_threads_closed',
    'diagnostic_mutex_released', 'parent_caps_unchanged',
)
BEHAVIOR_FORBIDDEN = (
    'filecenter_http_mutex_device_verified', 'filecenter_audio_startup_mutex_device_verified',
    'filecenter_parent_expiry_mutex_device_verified', 'filecenter_media_row_lock_device_verified',
    'blocking_file_io_preemption_verified', 'phone_interoperability_verified',
)
BEHAVIOR_COUNTS = ('diagnostic_threads', 'diagnostic_threads_closed_count')


# This literal is inserted only into the fixed diagnostic carrier body. It
# never substitutes a production class, method, lock, clock, guard or Owner.
BEHAVIOR_DEFINITIONS = r'''
behavior_rows=[];behavior_lock=None;behavior_held=False;behavior_module=None
behavior_methods=None;behavior_parent=None;behavior_deadline_row=None;behavior_cancel_row=None
behavior_deadline=None;behavior_close_started=None;behavior_error=None
def behavior_media(row):
 row['entered']=True;row['begin']=time.monotonic()
 try:
  need(behavior_module._Companion.media_row is behavior_methods[0])
  behavior_methods[0](filecenter,{'cap':'0'*64},deadline=row['deadline'])
  row['returned']=True
 except BaseException as error:row['failure']=error
 finally:
  row['end']=time.monotonic();row['ended']=True;row['event'].set()
def behavior_thread(deadline):
 row=dict(thread=None,original=None,initialized=False,start_called=False,
  start_returned=False,entered=False,ended=False,returned=False,failure=None,
  begin=None,end=None,deadline=deadline,event=threading.Event())
 behavior_rows.append(row)
 thread=threading.Thread.__new__(threading.Thread);row['thread']=row['original']=thread
 threading.Thread.__init__(thread,target=behavior_media,args=(row,))
 row['initialized']=True;thread.daemon=True;row['start_called']=True
 thread.start();row['start_returned']=True
 return row
def behavior_waiting(row,until):
 need(type(until)is float and until<=behavior_parent[0])
 while time.monotonic()<until:
  if row['ended']:return False
  ident=row['original'].ident
  frame=sys._current_frames().get(ident) if ident is not None else None
  for unused in range(32):
   if frame is None:break
   if frame.f_code is behavior_methods[1].__code__ and frame.f_lineno==59:
    value=frame.f_locals.get('self')
    if (type(value)is behavior_module._MediaLock and value.companion is filecenter
        and value.lock is behavior_lock):return True
   frame=frame.f_back
  row['event'].wait(min(0.002,max(0.0,until-time.monotonic())))
 return False
def behavior_join(row,until):
 need(type(until)is float and until<=behavior_parent[1])
 if row['initialized']and row['start_returned']:
  need(row['thread']is row['original']and row['original']is not threading.current_thread())
  row['original'].join(max(0.0,until-time.monotonic()))
 return (row['initialized']and row['start_called']and row['start_returned']
  and row['entered']and row['ended']and row['original'].is_alive()is False)
def behavior_failure(row,allowed):
 error=row['failure']
 return (row['returned']is False and type(error)is ValueError and len(error.args)==1
  and error.args[0]in allowed)
'''

BEHAVIOR_ACTIONS = r'''
 behavior_module=ticket['module'];behavior_lock=filecenter.media_lock
 behavior_methods=(behavior_module._Companion.media_row,behavior_module._MediaLock.__enter__,
  behavior_module._MediaLock.__exit__,behavior_module._Companion.check)
 behavior_parent=(filecenter.until,original.parent_cleanup_until)
 need(filecenter.worker is threading.current_thread()and owner.worker is filecenter.worker
  and filecenter.until is owner.original_until and filecenter.until is original.until
  and original.parent_until==parent_until and original.parent_cleanup_until==parent_cleanup_until
  and owner._filecenter_definitions_current()is True and filecenter.media==[])
 need(behavior_methods[1].__code__.co_firstlineno==54)
 need(time.monotonic()+2.0<behavior_parent[0])
 need(behavior_lock.acquire(False)is True);behavior_held=True
 facts['actual_media_mutex_original_held']=True
 behavior_deadline=float(min(behavior_parent[0],time.monotonic()+0.25))
 behavior_deadline_row=behavior_thread(behavior_deadline)
 facts['short_media_deadline_wait_observed']=behavior_waiting(behavior_deadline_row,behavior_deadline)
 need(facts['short_media_deadline_wait_observed'])
 need(behavior_join(behavior_deadline_row,min(behavior_parent[0],behavior_deadline+1.0)))
 facts['short_media_waiter_exited_while_held']=behavior_held
 facts['short_media_deadline_rejected']=behavior_failure(behavior_deadline_row,('filecenter_media_lock_deadline',))
 need(facts['short_media_deadline_rejected']and behavior_deadline_row['begin']<behavior_deadline
  and behavior_deadline_row['end']>=behavior_deadline)
 behavior_lock.release();behavior_held=False
 probe=behavior_thread(float(min(behavior_parent[0],time.monotonic()+0.5)))
 need(behavior_join(probe,min(behavior_parent[0],time.monotonic()+1.0)))
 facts['media_mutex_usable_after_short_deadline']=behavior_failure(probe,('invalid_media_cap',))
 need(facts['media_mutex_usable_after_short_deadline'])
 need(behavior_lock.acquire(False)is True);behavior_held=True
 behavior_cancel_row=behavior_thread(None)
 facts['owner_close_cancellation_wait_observed']=behavior_waiting(behavior_cancel_row,
  float(min(behavior_parent[0],time.monotonic()+1.0)))
 need(facts['owner_close_cancellation_wait_observed'])
 behavior_close_started=time.monotonic()
 need(behavior_close_started<behavior_parent[0])
'''

BEHAVIOR_FINISH = r'''
 if behavior_module is not None:
  try:
   facts['actual_owner_media_methods_unchanged']=(
    behavior_module._Companion.media_row is behavior_methods[0]
    and behavior_module._MediaLock.__enter__ is behavior_methods[1]
    and behavior_module._MediaLock.__exit__ is behavior_methods[2]
    and behavior_module._Companion.check is behavior_methods[3]
    and owner._filecenter_definitions_current()is True)
   finish_until=min(behavior_parent[1],filecenter.cleanup_until if filecenter.cleanup_until is not None
    else behavior_parent[1])
   try:
    if behavior_held and behavior_cancel_row is not None:
     facts['owner_close_waiter_exited_while_held']=behavior_join(behavior_cancel_row,float(finish_until))and behavior_held
     if not facts['owner_close_waiter_exited_while_held']:retain(ValueError('mutex_cancel_pending_while_held'))
   except BaseException as error:retain(error)
   finally:
    if behavior_held:
     try:
      need(behavior_lock is filecenter.media_lock and threading.current_thread()is filecenter.worker)
      behavior_lock.release();behavior_held=False
     except BaseException as error:retain(error)
   facts['diagnostic_mutex_released']=behavior_held is False
   finished=[behavior_join(row,float(finish_until))for row in behavior_rows]
   facts['diagnostic_threads']=len(behavior_rows)
   facts['diagnostic_threads_closed_count']=sum(value is True for value in finished)
   facts['diagnostic_threads_closed']=len(behavior_rows)==3 and all(finished)
   if behavior_cancel_row is not None and behavior_close_started is not None:
    facts['owner_close_waiter_exited']=behavior_cancel_row['ended']and behavior_cancel_row['original'].is_alive()is False
    facts['owner_close_cancellation_rejected']=behavior_failure(behavior_cancel_row,
     ('filecenter_session_ended','original_owner_changed'))
    need(behavior_cancel_row['end']is not None and behavior_cancel_row['end']>=behavior_close_started)
   facts['parent_caps_unchanged']=(filecenter.until is behavior_parent[0]
    and owner.original_until is behavior_parent[0]and original.until is behavior_parent[0]
    and original.parent_until==parent_until and original.parent_cleanup_until is behavior_parent[1]
    and original.parent_cleanup_until==parent_cleanup_until)
  except BaseException as error:behavior_error=error;retain(error)
  if not facts['diagnostic_threads_closed']:retain(ValueError('diagnostic_thread_pending'))
  if not all(facts[key]is True for key in (
   'actual_owner_media_methods_unchanged','actual_media_mutex_original_held',
   'short_media_deadline_wait_observed','short_media_deadline_rejected',
   'short_media_waiter_exited_while_held','media_mutex_usable_after_short_deadline',
   'owner_close_cancellation_wait_observed','owner_close_cancellation_rejected',
   'owner_close_waiter_exited','owner_close_waiter_exited_while_held',
   'diagnostic_threads_closed','diagnostic_mutex_released',
   'parent_caps_unchanged')):retain(ValueError('mutex_behavior_refused'))
'''


def need(value):
    if value is not True:
        raise ValueError('source_shape')


def fixed(inputs, row):
    raw = inputs.get(row[0], (BASE / row[0]).read_bytes())
    inputs[row[0]] = raw
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:])
    return raw


def source_parent(inputs):
    raw = fixed(inputs, MOTHER)
    names = {'need', 'fixed', 'derive', 'boundary'}
    chosen = [node for node in ast.parse(raw).body if
              isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
              isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in chosen if isinstance(node, ast.FunctionDef)} == names)
    value = types.ModuleType('_mutex_behavior_source_parent_only')
    value.__file__ = str(BASE / MOTHER[0])
    exec(compile(ast.Module(body=chosen, type_ignores=[]), value.__file__, 'exec'), value.__dict__)
    need(all(name not in value.__dict__ for name in ('load', 'main')))
    return value


def derive(raw):
    original = raw
    tree = ast.parse(raw)
    bodies = [node.value for node in tree.body if isinstance(node, ast.Assign) and
              any(isinstance(target, ast.Name) and target.id == 'SERVICE_BODY' for target in node.targets)]
    need(len(bodies) == 1)
    old_body = ast.literal_eval(bodies[0])
    body = old_body
    edits = (
        ('def error_detail(error):\n', BEHAVIOR_DEFINITIONS + '\ndef error_detail(error):\n'),
        ("      and ticket['create_returned']is True and ticket['sources']==tuple(decoded[1:]))\n",
         "      and ticket['create_returned']is True and ticket['sources']==tuple(decoded[1:]))\n" + BEHAVIOR_ACTIONS),
        ("   close_error=error;retain(error)\n try:\n  facts['source_identity_verified']=source_verified\n",
         "   close_error=error;retain(error)\n" + BEHAVIOR_FINISH +
         " try:\n  facts['source_identity_verified']=source_verified\n"),
        ("  facts['resource_pending']=not closed\n",
         "  closed=closed and facts['diagnostic_threads_closed']and facts['diagnostic_mutex_released']\n"
         "  facts['resource_pending']=not closed\n"),
        (" print('SERVICE_RESULT='+repr(facts))\n",
         " print('SERVICE_RESULT='+repr(facts))\n"
         " if behavior_deadline_row is not None and behavior_cancel_row is not None:\n"
         "  print('PRIVATE_MUTEX_BEHAVIOR_TIMES='+repr((behavior_deadline,behavior_deadline_row['begin'],\n"
         "   behavior_deadline_row['end'],behavior_close_started,behavior_cancel_row['begin'],behavior_cancel_row['end'])))\n"),
    )
    for before, after in edits:
        need(body.count(before) == 1)
        body = body.replace(before, after)
    ast.parse(body, feature_version=(3, 5))
    segment = ast.get_source_segment(raw.decode('ascii'), bodies[0])
    need(segment.startswith("r'''\n") and segment.endswith("'''"))
    changes = (
        ('SELF = ' + repr(MOTHER[0]), 'SELF = ' + repr(SELF), 1),
        ("CMD = 'HOST_MTA_FORMAL_SEND_FC_MUTEX_SERVICE_V1_CHECK.cmd'", 'CMD = ' + repr(CMD), 1),
        ('formal-send-fc-mutex-service-v1-', 'formal-send-fc-mutex-behavior-v1-', 1),
        ('SERVICE_FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS',
         'BOOL_FIELDS = BOOL_FIELDS + ' + repr(BEHAVIOR_REQUIRED + BEHAVIOR_FORBIDDEN) + '\n' +
         'COUNT_FIELDS = COUNT_FIELDS + ' + repr(BEHAVIOR_COUNTS) + '\n' +
         'BEHAVIOR_REQUIRED = ' + repr(BEHAVIOR_REQUIRED) + '\n' +
         'BEHAVIOR_FORBIDDEN = ' + repr(BEHAVIOR_FORBIDDEN) + '\n' +
         'SERVICE_FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS', 1),
        (segment, "r'''" + body + "'''", 1),
        ('formal-send-fc-mutex-v1-service-diagnostic', KIND, 3),
        ("value['mta_http_requests'] == 0 and value['mta_http_threads'] == 1)",
         "value['mta_http_requests'] == 0 and value['mta_http_threads'] == 1 and\n"
         "        all(value[name] is True for name in BEHAVIOR_REQUIRED) and\n"
         "        all(value[name] is False for name in BEHAVIOR_FORBIDDEN) and\n"
         "        value['diagnostic_threads'] == value['diagnostic_threads_closed_count'] == 3)", 1),
        ('Fixed mutex real service and FileCenter diagnostic. Default is PC-only source construction.',
         'Fixed real Owner/no-file mutex behavior diagnostic. Default is PC-only source construction.', 1),
        ('creates original nine-source FileCenter, closes immediately.',
         'creates original nine-source FileCenter, runs fixed no-file mutex methods, closes originals.', 1),
        ('Parent60+cleanup60, outer180/HOST210; no wait, renewal, credentials, business HTTP, UI, audio, transfer or scan.',
         'Parent60+cleanup60, outer180/HOST210 unchanged; short caller mutex cap and original Owner-close cancellation only.', 1),
        ('Carrier fd0 is not consumed by the service; no physical EOF claim.',
         'Three real diagnostic threads are retained and joined; no parent-expiry, HTTP, audio callback, row-lock or file-IO proof. Carrier fd0 is not consumed; no physical EOF claim.', 1),
    )
    ledger = []
    for before, after, count in changes:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count)
        positions = [index for index in range(len(raw)) if raw.startswith(before, index)]
        for offset in reversed(positions):
            raw = raw[:offset] + after + raw[offset + len(before):]
            ledger.append((offset, before, after))
    inverse = raw
    for offset, before, after in reversed(ledger):
        need(inverse[offset:offset + len(after)] == after)
        inverse = inverse[:offset] + before + inverse[offset + len(after):]
    need(inverse == original and ast.dump(ast.parse(inverse), include_attributes=True) ==
         ast.dump(ast.parse(original), include_attributes=True))
    old_tree, new_tree = ast.parse(original), ast.parse(raw)
    old_defs = {node.name: ast.get_source_segment(original.decode('ascii'), node) for node in old_tree.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    new_defs = {node.name: ast.get_source_segment(raw.decode('ascii'), node) for node in new_tree.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    need(set(old_defs) == set(new_defs))
    changed = {name for name in old_defs if old_defs[name] != new_defs[name]}
    need(changed == {'service_result', 'service_complete', 'main'})
    return raw, dict(complete_byte_inverse=True, complete_positioned_ast_inverse=True,
        finite_host_edits=len(ledger), changed_host_methods=sorted(changed),
        diagnostic_body_insertions_only=True, production_methods_guards_clocks_caps_unchanged=True,
        old_main_executed=False, derived_host_bytes=len(raw),
        derived_host_sha256=hashlib.sha256(raw).hexdigest())


def load():
    inputs = {}
    parent = source_parent(inputs)
    old, parent_proof = parent.derive(parent.fixed(inputs, parent.MOTHER))
    raw, proof = derive(old)
    value = types.ModuleType('_formal_send_fc_mutex_behavior_v1_fixed_carrier')
    value.__file__ = str(BASE / SELF)
    exec(compile(raw, '<mutex-owner-behavior-v1-fixed-carrier>', 'exec'), value.__dict__)
    need(value.SELF == SELF and value.CMD == CMD and value.CATALOG == parent.CATALOG and
         value.OUTER == parent.OUTER and value.BOOT == parent.BOOT and value.OWNER == parent.OWNER)
    facts = dict(scope='SOURCE_PROVENANCE_NOT_RUNTIME', boundary_complete=False,
        original_mutex_service_mother=list(MOTHER), original_service_mother=list(parent.MOTHER),
        original_package_carrier_proof=parent_proof, behavior_source_proof=proof,
        ordinary_root=parent.ROOT, original_parent_seconds=60, original_cleanup_seconds=60,
        original_alarm_seconds=180, original_host_seconds=210,
        device_program_uses_fixed_actual_owner=True, production_methods_replaced=False,
        fixture_owner_supplied=False, original_guards_replaced=False, deadline_extended=False,
        filecenter_parent_expiry_mutex_device_verified=False,
        filecenter_http_mutex_device_verified=False, filecenter_audio_startup_mutex_device_verified=False,
        filecenter_media_row_lock_device_verified=False, blocking_file_io_preemption_verified=False,
        gui19_staged=False, fc9_staged=False, ui_started=False, rf_requested=False,
        phone_tested=False, full_network_restore_verified=False, old_tests_run=0,
        old_main_executed=False)
    value._MUTEX_SERVICE_SOURCE_FACTS = facts
    inherited = value.make_program

    def make_program(snapshot):
        for path, raw in inputs.items():
            need(path not in snapshot or snapshot[path] == raw)
            snapshot[path] = raw
        for path in (SELF, CMD, TEST_CMD):
            raw = (BASE / path).read_bytes()
            need(path not in snapshot or snapshot[path] == raw)
            snapshot[path] = raw
        closure = parent.boundary(snapshot)
        facts.update(boundary_complete=True, package_closure=closure,
                     fc9_sources=9, fc9_bytes=101682, fc9_cap=131072,
                     in_memory_sources=10, in_memory_source_bytes=125742)
        program = inherited(snapshot)
        facts.update(program_prepared=True, program_bytes=len(program),
                     program_sha256=hashlib.sha256(program).hexdigest())
        return program

    value.make_program = make_program
    return value


def main():
    # Only the inherited explicit --check-device authorizes the actual carrier.
    return load().main()


if __name__ == '__main__':
    raise SystemExit(main())
