"""Private after-return cache projection, not a runtime/closure validator.

TARGET_FRAGMENT is inserted only after the frozen worker.run_fixed returned.
It never calls an actor, clock, IO, close/status/check/finish or process method.
The original 17-field RESULT and every business/closure predicate stay intact.
Only existing parent read_values are copied: stdout prefix <=8192 bytes,
stderr <=16384 bytes. Prefix/truncation facts are explicit; no new pipe read.
The existing carrier stdout remains private and is not included in RESULTS.zip.
No child-internal trace is invented: Entry catches collect errors and returns 1.
"""

TARGET_FRAGMENT = b'''
def _private_send_ui_preflight_after_return_v1(worker, component):
    def need(value):
        if value is not True: raise ValueError('private_cache_binding')
    def boolean(value):
        return value if type(value) is bool else None
    def integer(value, maximum):
        return value if type(value) is int and 0 <= value <= maximum else None
    def error_kind(value):
        if value is None: return None
        if not isinstance(value, BaseException): return 'untyped'
        name = type(value).__name__
        return name if type(name) is str and len(name) <= 96 and name.isidentifier() and all(ord(char) < 128 for char in name) else 'other'
    def row_facts(row):
        need(type(row) is dict)
        error = row.get('close_error')
        return dict(closed=boolean(row.get('closed')), unknown=boolean(row.get('unknown')),
            open_called=boolean(row.get('open_called', row.get('called'))),
            returned=boolean(row.get('returned')), close_called=boolean(row.get('close_called')),
            fd_original_same=row.get('fd') is row.get('fd_original'),
            fd_original_typed=integer(row.get('fd_original'), 2147483647) is not None,
            metadata_original_same=(row.get('metadata') is row.get('metadata_original')
                if type(row.get('metadata')) is tuple and type(row.get('metadata_original')) is tuple else None),
            close_return_none=row.get('close_return') is None,
            close_error_kind=error_kind(error), close_failure_kind=error_kind(row.get('close_failure')),
            close_error_ebadf=isinstance(error, OSError) and type(error.errno) is int and error.errno == 9,
            failure_kind=error_kind(row.get('failure')))
    def payload(row, cap, source_cap):
        values = row.get('read_values')
        need(type(values) is list and len(values) <= 4096 and
             all(type(value) is bytes and len(value) <= 65536 for value in values))
        total = sum(len(value) for value in values)
        # Original read count is cap+1-current_bytes. Its one overflow byte is
        # retained before the original budget rejection; it is DATA, not permission.
        need(total <= source_cap+1 and type(row.get('bytes')) is int and row['bytes'] == total)
        prefix, copied = [], 0
        for value in values:
            if copied < cap:
                part = value[:cap-copied]; prefix.append(part); copied += len(part)
        raw = b''.join(prefix)
        return dict(read_count=len(values), cached_bytes=total, prefix_bytes=len(raw),
            prefix_hex=raw.hex(), truncated=total > cap, cached_over_source_cap=total > source_cap,
            empty_read_count=sum(value == b'' for value in values), eof=boolean(row.get('eof')))
    result = dict(kind='sender-preflight-after-return-cache-v1', available=False,
        grants_closure=False, child_internal_inventory_accessed=False,
        source_limits=dict(parent_stdout=262144, parent_stderr=16384,
                           diagnostic_stdout_prefix=8192, diagnostic_stderr=16384))
    fields = ('complete','ui_ready','credentials_removed','original_ui_exited','candidate_exited',
        'owner_closed','guardian_exited','stock_restored','worker_fds_closed','resource_pending',
        'automatic_rf_action','receive_worker_started','filecenter_parent_deadline_verified',
        'filecenter_parent_deadline_wired','smoke_requested','automatic_stop_seconds','reason')
    need(type(component) is dict and set(component) == set(fields))
    namespace = worker.__dict__
    scope = namespace.get('_RETAINED')
    if scope is None: return result
    need(type(scope) is namespace.get('_UiScope'))
    sd = scope.__dict__
    need(sd.get('closing') is True)
    sender, st = sd.get('sender'), sd.get('sender_ticket')
    if st is None: return result
    need(type(st) is dict and st.get('constructed') is True and sender is st.get('original') and
         type(sender) is st.get('creator') and
         st['creator'].__init__.__globals__ is sd['sender_module'].__dict__)
    sender_data = sender.__dict__
    owner, ot = sender_data.get('owner'), sender_data.get('owner_ticket')
    if ot is None: return result
    need(type(ot) is dict and ot.get('constructed') is True and owner is ot.get('partial') and
         type(owner) is ot.get('creator') and
         ot['creator'].__init__.__globals__ is sender_data['owner_module'].__dict__)
    od = owner.__dict__
    need(type(owner) is od.get('_startup_owner_type_original') and
         od.get('_startup_namespace_original') is sender_data['owner_module'].__dict__ and
         od.get('close_called') is True)
    parent, pt = od.get('send_preflight_parent'), od.get('send_preflight_ticket')
    if pt is None: return result
    loader, lt = sender_data.get('loader'), sender_data.get('loader_ticket')
    need(type(lt) is dict and lt.get('constructed') is True and loader is lt.get('partial') and
         type(loader) is lt.get('creator') and od.get('loader') is loader)
    ld = loader.__dict__
    need(type(ld.get('modules')) is dict and type(ld.get('module_originals')) is list and
         len(ld['module_originals']) == 32)
    module = ld['modules'].get('mta_go_readonly_parent')
    matches = [row for row in ld['module_originals'] if type(row) is tuple and len(row) == 3 and
               row[0] == 'mta_go_readonly_parent']
    need(len(matches) == 1 and matches[0][1] is module and matches[0][2] is module.__dict__)
    cls = module.__dict__.get('ReadonlyDataParent')
    need(type(pt) is dict and pt.get('creator') is cls and pt.get('constructed') is True and
         pt.get('ended') is True and parent is pt.get('partial') and parent is pt.get('returned') and
         type(parent) is cls and cls.__init__.__globals__ is module.__dict__)
    pd = parent.__dict__
    need(pd.get('ended') is True)
    failure = pd.get('failure')
    need(failure is pt.get('failure') and
         (failure is None or isinstance(failure, BaseException)))
    result['owner_preflight'] = {name:boolean(pt.get(name)) for name in
        ('constructor_called','constructed','collect_called','ended','unknown')}
    result['owner_preflight'].update(collect_return_present=pt.get('collect_return') is not None,
        report_same=pt.get('collect_return') is od.get('send_preflight_report'),
        failure_kind=error_kind(failure), failure_same_parent=True)
    result['owner_cached'] = {name:boolean(od.get(name)) for name in
        ('close_called','close_complete','directory_close_called','directory_close_complete')}
    result['sender_cached'] = {name:boolean(sender_data.get(name)) for name in
        ('close_called','close_complete','owner_close_return','pending')}
    result['parent_cached'] = {name:boolean(pd.get(name)) for name in
        ('attempted','ended','closed','close_attempted','unknown','cleanup_attempted')}
    result['parent_cached'].update(failure_kind=error_kind(failure),
        parent_child_failed_arg=isinstance(failure, BaseException) and failure.args == ('parent_child_failed',),
        original_error_code_present=isinstance(failure, BaseException) and 'code' in failure.__dict__,
        cleanup_error_kind=error_kind(pd.get('cleanup_error')),
        report_present=pd.get('result') is not None)
    # Only one pinned args reason; no arbitrary error text or new validation.
    trace, drain_match, collect_match, frames = (None if failure is None else failure.__traceback__), False, False, 0
    while trace is not None and frames < 32:
        frame = trace.tb_frame
        if frame.f_globals is module.__dict__ and frame.f_locals.get('self') is parent:
            drain_match = drain_match or frame.f_code is cls._drain_and_wait.__code__
            collect_match = collect_match or frame.f_code is cls.collect.__code__
        frames += 1; trace = trace.tb_next
    result['parent_failure_trace_cached'] = dict(drain_self_same=drain_match,
        collect_self_same=collect_match, inspected=frames, truncated=trace is not None)
    rows, history = pd.get('rows'), pd.get('row_history')
    need(type(rows) is list and rows is pd.get('rows_original') and
         type(history) is list and history is pd.get('row_history_original') and
         len(rows) == len(history) <= 9 and all(a is b for a,b in zip(rows,history)))
    result['parent_fd_rows'] = tuple(row_facts(row) for row in rows)
    result['parent_close_error_count'] = (len(pd['close_errors'])
        if type(pd.get('close_errors')) is list and len(pd['close_errors']) <= 32 else None)
    process, ticket = pd.get('process'), pd.get('process_attempt')
    if ticket is not None:
        need(type(ticket) is dict and ticket is pd.get('process_attempt_original') and
             process is pd.get('process_original') and process is ticket.get('process') and
             type(process) is module.__dict__['subprocess'].Popen)
        pipes = ticket.get('pipes')
        need(type(pipes) is tuple and len(pipes) == 2 and
             all(type(row) is dict and any(row is original for original in rows) for row in pipes) and
             pipes[0].get('role') == 'stdout' and pipes[1].get('role') == 'stderr' and
             ticket.get('stdout') is pipes[0].get('raw_original') and
             ticket.get('stderr') is pipes[1].get('raw_original'))
        wait = ticket.get('wait_return')
        if type(wait) is not int or not -255 <= wait <= 255: wait = None
        w = ticket.get('wait_ticket')
        methods = pd.get('process_methods')
        need(type(methods) is tuple and methods is pd.get('process_methods_original') and len(methods) == 2)
        wait_bound = (type(w) is tuple and len(w) == 6 and w is ticket.get('wait_ticket_original') and
            w[0] is process and w[1] is pd.get('process_pid') and w[2] is methods[1] and
            w[3] is ticket.get('wait_return') and w[4] is pipes[0].get('eof_ticket') and
            w[5] is pipes[1].get('eof_ticket'))
        result['child_cached'] = {name:boolean(ticket.get(name)) for name in
            ('called','returned','unknown','wait_called','waited','reaped')}
        result['child_cached'].update(wait_return=wait, wait_error_kind=error_kind(ticket.get('wait_error')),
            wait_ticket_bound=wait_bound, returncode_same=process.__dict__.get('returncode') is ticket.get('wait_return'))
        eof_bindings = []
        for row in pipes:
            eof = row.get('eof_ticket')
            eof_bindings.append(type(eof) is tuple and len(eof) == 7 and eof[0] is process and
                eof[1] is pd.get('process_pid') and eof[2] is row and
                eof[3] is row.get('raw_original') and eof[4] is row.get('fd_original') and
                eof[5] is row.get('metadata_original') and type(eof[6]) is bytes and eof[6] == b'')
        result['child_cached']['eof_ticket_bindings'] = tuple(eof_bindings)
        result['stdout_cached'] = payload(pipes[0],8192,262144)
        result['stderr_cached'] = payload(pipes[1],16384,16384)
        errparts = pd.get('stderr_parts')
        need(type(errparts) is list and len(errparts) <= 4096 and
             all(type(part) is bytes for part in errparts) and
             sum(len(part) for part in errparts) == pd.get('stderr_bytes') <= 16385)
        result['stderr_cached']['parts_same_bytes'] = (b''.join(errparts) ==
            b''.join(pipes[1]['read_values']))
    reader, functions = pd.get('reader'), pd.get('packet_functions')
    if reader is not None:
        need(type(functions) is tuple and functions is pd.get('packet_functions_original') and
             len(functions) == 5 and reader is pd.get('reader_original') and type(reader) is functions[1])
        rd = reader.__dict__; parts = rd.get('parts')
        need(type(parts) is list and len(parts) <= 4096 and all(type(part) is bytes for part in parts) and
             sum(len(part) for part in parts) <= 262144)
        result['reader_cached'] = dict(size=integer(rd.get('size'),262144),
            expected=integer(rd.get('expected'),262144), ended=boolean(rd.get('ended')),
            value_present=rd.get('value') is not None, failure_kind=error_kind(rd.get('failure')),
            part_count=len(parts), parts_byte_count=sum(len(part) for part in parts))
    dirs = od.get('directory_tickets')
    need(type(dirs) is list and dirs is od.get('_directory_tickets_original') and len(dirs) <= 2)
    directory_rows = []
    for index, dt in enumerate(dirs):
        value = od.get('user_directory' if index == 0 else 'received_directory')
        original = od.get('_user_directory_original' if index == 0 else '_received_directory_original')
        need(type(dt) is dict and value is original and value is dt.get('value') and
             type(value) is od.get('directory_type') and dt.get('complete') is True)
        vd = value.__dict__; dr, originals = vd.get('rows'), vd.get('_row_originals')
        need(type(dr) is list and dr is dt.get('rows') and type(originals) is tuple and
             originals is dt.get('row_originals') and len(dr) == len(originals) <= 16 and
             all(a is b for a,b in zip(dr,originals)))
        directory_rows.append(dict(close_called=boolean(vd.get('_close_called')),
            closed=boolean(vd.get('_closed')), failure_kind=error_kind(vd.get('failure')),
            rows=tuple(row_facts(row) for row in dr)))
    result['owner_directory_cache'] = tuple(directory_rows)
    # Exact-class held Registry cache lacks a separate original anchor.
    state = od.get('state')
    if state is not None:
        service = ld['modules'].get('mta_service')
        files = ld['modules'].get('mta_files')
        for name, actual in (('mta_service',service),('mta_files',files)):
            anchors = [row for row in ld['module_originals'] if type(row) is tuple and
                       len(row) == 3 and row[0] == name]
            need(len(anchors) == 1 and anchors[0][1] is actual and anchors[0][2] is actual.__dict__)
        need(od.get('state_complete') is True and state is od.get('_state_original') and
             type(state) is od.get('_service_type_original') and type(state) is service.__dict__['State'])
        state_data = state.__dict__; registry = state_data.get('registry')
        need(type(registry) is files.__dict__['FileRegistry'])
        registry_data = registry.__dict__; resources = registry_data.get('_resources')
        need(type(resources) is list)
        resources_observed = []
        for resource in resources[:256]:
            need(type(resource) is files.__dict__['_FileResource'] and
                 resource.__dict__.get('registry') is registry)
            data = resource.__dict__
            resources_observed.append({name:boolean(data.get(name)) for name in
                ('opening','raw_owned','claimed','transfer_unknown','attempted',
                 'wrapper_closed','fd_closed','pending','verified')})
        result['registry_cache'] = dict(held_exact_class=True,
            separate_original_anchor_available=False, resource_count=len(resources),
            blocked=boolean(registry_data.get('_blocked')), inspected=len(resources_observed),
            truncated=len(resources)>256, resources=tuple(resources_observed[:8]),
            rows_truncated=len(resources_observed)>8,
            true_counts={name:sum(row[name] is True for row in resources_observed) for name in
                         ('wrapper_closed','fd_closed','pending','verified')})
        result['state_cache'] = {name:boolean(state_data.get(name)) for name in
            ('closing','wifi_restore_pending','radio_restore_pending')}
        result['state_cache'].update(session_present=state_data.get('session') is not None,
            operation_present=state_data.get('operation') is not None)
    result['available'] = True
    return result
try:
    _private_send_preflight_row_v1 = _private_send_ui_preflight_after_return_v1(worker, component)
    _private_send_preflight_text_v1 = repr(_private_send_preflight_row_v1)
    if len(_private_send_preflight_text_v1) > 65536: raise ValueError('private_projection_cap')
    print('PRIVATE_SEND_PREFLIGHT_AFTER_RETURN_V1=' + _private_send_preflight_text_v1)
except BaseException:
    print('PRIVATE_SEND_PREFLIGHT_AFTER_RETURN_V1=' + repr(dict(
        kind='sender-preflight-after-return-cache-v1', available=False,
        projection_error=True, grants_closure=False)))
'''
