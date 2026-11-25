"""One original, bounded receive trial; no IO or restoration authority.

Only the fixed Owner constructs this object, in its original startup worker,
after the actual private collection and startup scope have been closed there.
``requested`` is the Owner's fixed trusted entry policy, not capability DATA or
an HTTP/UI argument. It authorizes only one original Operation/Session claim.
The original read-only publication barrier, native probe objects, source realm,
asset readbacks, Received binding and service cap remain strongly retained.

Later HTTP/Session calls inspect those original references and settled ledgers;
they never call Scope.closed/check_active, Collection.resources_closed,
Owner._now, a probe poll/wait, a filesystem or a restoration callback. The only
active limit check is the original time.monotonic service deadline. Revocation
and closed() do not check a deadline and never prevent original cleanup.
Neither construction, public facts nor Gate.closed certifies RF restoration,
phone compatibility or a completed transfer. Pending/history is never removed.
The Handoff DATA check consumes the already claimed original Operation/Session;
it is not RF permission, does not reopen available(), and permits only the
original worker or the original helper reader's capture entry. Its constructor
ticket is retained before __init__; a partial constructor never becomes usable.
Python 3.5 compatible. No injected IO, callbacks, paths or model entry exists.
"""
import errno
import hashlib
import math
import sys
import threading
import time
import types


SCHEMA = 'p011-fixed-receive-trial-v1'
MAX_ROWS = 8192
MAX_LIST = 4096
REASONS = frozenset((
    'not_requested', 'ready', 'claimed', 'revoked', 'expired',
    'owner_context', 'source_changed', 'startup_unknown', 'probe_unknown',
    'radio_unknown', 'radio_unavailable', 'radio_busy', 'network_spec_unknown',
    'barrier_unknown', 'state_not_idle', 'claim_changed', 'already_claimed',
    'session_unknown', 'owner_stopped', 'owner_closed', 'cancelled',
    'state_closing', 'operation_failed', 'session_failed',
    'not_started', 'clear', 'wrong_worker', 'deadline', 'unsupported_platform',
    'unsafe_anchor', 'anchor_changed', 'alias_changed', 'pending_exists',
    'pending_symlink', 'client_root_missing', 'client_history',
    'inventory_unknown', 'descriptor_unknown', 'io_error', 'close_unknown',
    'already_attempted',
))
REVOKE_REASONS = frozenset((
    'owner_stopped', 'owner_closed', 'cancelled', 'state_closing',
    'operation_failed', 'session_failed', 'expired', 'revoked',
))
_OWNER_NAMES = ('mta_client_service_owner', 'startup_readonly_private_owner')


class ReceiveTrialError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in REASONS else 'owner_context'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise ReceiveTrialError(code) from None


def _finite(value):
    return type(value) is float and math.isfinite(value) and 0 < value < 2 ** 53


def _same_method(value, instance, function):
    return (getattr(value, '__self__', None) is instance and
            getattr(value, '__func__', None) is function)


class FixedReceiveTrial(object):
    """Once-owned trial. Its retained originals are never reset or replaced."""
    def __init__(self, owner, barrier, requested):
        self.owner = self._owner_original = owner
        self.barrier = self._barrier_original = barrier
        self.requested = self._requested_original = requested
        self.state = self._state_original = getattr(owner, 'state', None)
        self.factory = self._factory_original = getattr(owner, 'factory', None)
        self.loader = self._loader_original = getattr(owner, 'loader', None)
        self.scope = self._scope_original = getattr(owner, 'startup_scope', None)
        self.collection = self._collection_original = getattr(owner, 'startup_result', None)
        self.ticket = self._ticket_original = getattr(self.scope, 'collector_ticket', None)
        self.snapshot = self._snapshot_original = getattr(self.collection, 'snapshot', None)
        self.received = self._received_original = getattr(owner, 'received_directory', None)
        self.until = self._until_original = getattr(owner, 'original_until', None)
        self.clock = self._clock_original = getattr(owner, 'clock', None)
        self.worker = self._worker_original = getattr(owner, 'worker', None)
        self.pid = self._pid_original = getattr(owner, 'pid', None)
        self.probes = self._probes_original = getattr(owner, 'probe_rows', None)
        self.assets = self._assets_original = getattr(owner, 'assets', None)
        self._lock = self._lock_original = threading.RLock()
        self.failure, self.failures = None, []
        self.claimed_operation = self._claimed_operation_original = None
        self.session = self._session_original = None
        self.claim_count = 0
        self.revoked = self.expired = False
        self.revoke_reason = None
        self.reason = 'owner_context'
        self._last = None
        self._startup_verified = self._probe_verified = self._radio_known = False
        self._barrier_clear = self._network_spec_verified = False
        self._attrs, self._lists, self._maps, self._definitions = [], [], [], []
        self._attrs_original, self._lists_original = self._attrs, self._lists
        self._maps_original, self._definitions_original = self._maps, self._definitions
        self._session_originals = self._claim_originals = None
        self._module = sys.modules.get('mta_receive_trial')
        self._namespace = globals()
        self._owner_type = type(owner)
        self._owner_namespace = getattr(owner, '_startup_namespace_original', None)
        self._modules = getattr(self.loader, 'modules', None)
        self._epoch = getattr(self.state, 'native_epoch', None)
        try:
            self._construction_context()
            self._retain_definitions()
            self._retain_startup()
            self._retain_probes_and_assets()
            self._retain_barrier()
            self._retention_originals = (tuple(self._attrs), tuple(self._lists),
                tuple(self._maps), tuple(self._definitions))
            self.reason = self._machine_reason()
        except BaseException as error:
            self.failure = error
            self.failures.append(error)
            if type(error) is ReceiveTrialError:
                self.reason = error.code
            raise

    def __repr__(self):
        return '<original bounded receive trial; no restoration certificate>'

    def _construction_context(self):
        owner, ns, module = self.owner, self._owner_namespace, self._module
        boot = sys.modules.get('mta_client_receive_boot')
        if (type(self.requested) is not bool or type(ns) is not dict or
                ns.get('__name__') not in _OWNER_NAMES or
                ns.get('FixedStateServiceOwner') is not self._owner_type or
                owner._startup_owner_type_original is not self._owner_type or
                type(module) is not types.ModuleType or module.__dict__ is not globals() or
                module.FixedReceiveTrial is not FixedReceiveTrial or
                __name__ != 'mta_receive_trial' or
                type(self._modules) is not dict or self._modules.get('mta_receive_trial') is not module or
                type(boot) is not types.ModuleType or owner.boot is not boot or
                type(self.loader) is not boot.BootSourceLoader or
                type(owner.io) is not ns.get('_LinuxIo') or owner.io is not owner.original_io or
                owner.worker is not threading.current_thread() or self.worker is not owner.worker or
                type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff or
                self.clock is not time.monotonic or not _finite(self.until) or
                owner.until is not self.until or self.loader._original_until is not self.until or
                self.loader.clock is not self.clock or owner.started is not True or
                owner.state_complete is not True or owner.startup_complete is not True or
                owner.startup_failure is not None or owner.startup_window_closed is not True or
                owner.server_called is not False or owner.server is not None or owner.thread is not None or
                owner.close_called is not False or owner.stop_called is not False or
                owner.receive_trial_requested is not self.requested or
                owner._receive_trial_requested_original is not self.requested or
                owner.receive_trial is not self or owner._receive_trial_original is not self or
                owner._receive_trial_module_original is not module or
                owner._receive_trial_type_original is not FixedReceiveTrial):
            _fail('owner_context')
        ticket = owner._receive_trial_ticket
        if (type(ticket) is not dict or ticket.get('creator') is not FixedReceiveTrial or
                ticket.get('partial') is not self or ticket.get('constructor_called') is not True or
                ticket.get('constructed') is not False or ticket.get('returned') is not None or
                ticket.get('ended') is not False or ticket.get('failure') is not None or
                type(ticket.get('unknown')) is not bool):
            _fail('owner_context')
        self._owner_ticket = ticket

    def _definition(self, target, name):
        value = getattr(target, name, None)
        if value is None: _fail('source_changed')
        self._definitions.append((target, name, value))
        return value

    def _attributes(self, target, names):
        if target is None or len(self._attrs) >= MAX_ROWS: _fail('startup_unknown')
        values = []
        for name in names:
            if not hasattr(target, name): _fail('startup_unknown')
            values.append((name, getattr(target, name)))
        self._attrs.append((target, tuple(values)))

    def _list(self, value, mappings=False):
        if type(value) is not list or len(value) > MAX_LIST or len(self._lists) >= MAX_ROWS:
            _fail('inventory_unknown')
        self._lists.append((value, tuple(value)))
        if mappings:
            for row in value: self._mapping(row)

    def _mapping(self, value):
        if (type(value) is not dict or len(value) > 128 or len(self._maps) >= MAX_ROWS or
                any(type(key) is not str for key in value)):
            _fail('inventory_unknown')
        self._maps.append((value, tuple(sorted(value)), tuple((key, value[key]) for key in sorted(value))))

    def _retain_definitions(self):
        modules = self._modules
        self._roles = tuple((name, modules.get(name)) for name in (
            'mta_client_receive_factory', 'mta_client_startup_readonly', 'mta_storage',
            'mta_transfer_session', 'mta_receive_radio_baseline', 'mta_receive_network',
            'mta_receive_barrier', 'mta_service', 'mta_client_executor',
            'mta_client_state_bridge', 'mta_client_connect_handoff', 'mta_crypto'))
        for name, module in self._roles:
            if (type(module) is not types.ModuleType or module.__name__ != name or
                    sys.modules.get(name) is not module): _fail('source_changed')
        self._service = modules['mta_service']
        self._barrier_module = modules['mta_receive_barrier']
        self._startup_module = modules['mta_client_startup_readonly']
        self._factory_module = modules['mta_client_receive_factory']
        self._session_module = modules['mta_transfer_session']
        self._handoff_module = modules['mta_client_connect_handoff']
        self._crypto_module = modules['mta_crypto']
        self._state_type = self._definition(self._service, 'State')
        self._operation_type = self._definition(self._service, 'Operation')
        self._session_type = self._definition(self._session_module, 'TransferSession')
        self._handoff_type = self._definition(self._handoff_module, 'ReceiveConnectHandoff')
        self._crypto_type = self._definition(self._crypto_module, 'OpenSslCrypto')
        self._key_type = self._definition(self._crypto_module, 'KeyPair')
        self._handoff_init = self._definition(self._handoff_type, '__init__')
        for name in ('_check', 'capture', 'decrypt', 'claim_frame', 'cancel'):
            function = self._definition(self._handoff_type, name)
            if type(function) is not types.FunctionType or function.__globals__ is not self._handoff_module.__dict__:
                _fail('source_changed')
        self._definition(modules['mta_storage'], 'DirectoryBinding')
        self._barrier_type = self._definition(self._barrier_module, 'Barrier')
        self._collection_type = self._definition(self._startup_module, 'StartupCollection')
        self._scope_type = self._definition(self._factory_module, '_StartupReadScope')
        self._factory_type = self._definition(self._factory_module, 'FixedReceiveDeploymentFactory')
        for name in ('_context', '_now', '_startup_readonly', '_close_startup', 'close'):
            function = self._definition(self._owner_type, name)
            if type(function) is not types.FunctionType or function.__globals__ is not self._owner_namespace:
                _fail('source_changed')
        for name in ('__init__', '_new_operation_locked', '_run_operation', '_restore_owner', '_close_extra',
                     '_receive_handoff_constructed', '_receive_handoff_data_allowed', '_new_receive_handoff'):
            function = self._definition(self._state_type, name)
            if type(function) is not types.FunctionType or function.__globals__ is not self._service.__dict__:
                _fail('source_changed')
            if name == '_receive_handoff_data_allowed':
                self._state_handoff_data_authorizer = function
        self._session_init = self._definition(self._session_type, '__init__')
        self._definition(self._barrier_type, '__init__')
        self._definition(self._barrier_type, 'run')
        self._definition(self._barrier_module, '_LinuxIo')
        self._definition(self._startup_module, 'collect')
        self._definition(self._collection_type, 'resources_closed')
        self._definition(self._scope_type, 'closed')
        self._definition(self._scope_type, 'close')
        self._definition(self._factory_module, 'SOURCE_MANIFEST_SHA')
        self._definition(self._collection_type, '_definitions_now')
        self._definition(self._service, 'PrivateHelper')
        self._definition(self._service, 'StateClientBridge')
        self._definition(self._service, 'ReceiveConnectHandoff')
        self._definition(self._service.subprocess, 'Popen')
        self._definition(self._service, '_CAPABILITY_CREATOR')
        self._definition(self._service, 'capability')
        self._definition(self._service.json, 'dumps')
        self._definition(self._service.json, 'loads')
        self._definition(modules['mta_receive_radio_baseline'], 'normalize')
        self._definition(threading.Event, 'is_set')
        self._definition(threading.Event, 'set')
        for name in ('__init__', 'binds', 'available', 'claim', 'attach_session', 'allows',
                     '_handoff_matches', 'allows_handoff_data', 'revoke', 'closed', 'public_facts'):
            function = self._definition(FixedReceiveTrial, name)
            if type(function) is not types.FunctionType or function.__globals__ is not globals():
                _fail('source_changed')

    def _retain_startup(self):
        owner, state, scope, value = self.owner, self.state, self.scope, self.collection
        private = getattr(scope, 'private_modules', None)
        if (type(state) is not self._state_type or owner.state is not owner._state_original or
                owner.service is not self._service or type(self.factory) is not self._factory_type or
                owner.factory is not owner._startup_factory_original or
                type(scope) is not self._scope_type or scope is not owner._startup_scope_original or
                self.factory._startup_scope is not scope or scope.owner is not owner or scope.state is not state or
                scope.factory is not self.factory or scope.loader is not self.loader or
                scope.worker is not self.worker or scope.pid != self.pid or scope.clock is not self.clock or
                scope.original_until is not self.until or scope.received_directory is not self.received or
                state._trusted_receive_deployment_factory is not self.factory or
                state._service_until_original is not self.until or state._original_service_until is not self.until or
                self.received is not owner._received_directory_original or
                state._received_binding_original is not self.received or state._original_received_binding is not self.received or
                self.received.absolute_until is not self.until or self.received.clock is not self.clock or
                type(self.received) is not self._modules['mta_storage'].DirectoryBinding or
                type(self.ticket) is not dict or scope.collector_called is not True or
                self.ticket.get('creator') is not self._collection_type or self.ticket.get('returned') is not value or
                self.ticket.get('started') is not True or self.ticket.get('ended') is not True or
                self.ticket.get('failure') is not None or type(value) is not self._collection_type or
                value.scope is not scope or value.attempted is not True or value.ended is not True or
                value.success is not True or value.failure is not None or value.close_failure is not None or
                scope.close_called is not True or scope.close_complete is not True or
                scope.success is not True or scope.failure is not None or scope.read_ended is not True or
                type(private) is not dict or private is not scope._private_modules_original or
                value.modules is not private or type(self.snapshot) is not private['mta_p2p_client_init'].Snapshot or
                value.collector is not value._collector_original or value.collector._snapshot is not self.snapshot or
                len(value.collector._rounds) != 2 or value.collector._rounds[1] is not self.snapshot or
                len(value.status_rows) != 2 or len(value.reader_rows) != 3 or
                self._scope_type.closed(scope) is not True or
                self._collection_type.resources_closed(value) is not True):
            _fail('startup_unknown')
        self._private = private
        self._private_rows = tuple(sorted(private.items()))
        self._mapping(self.ticket)
        self._attributes(scope, ('owner', 'state', 'factory', 'loader', 'worker', 'pid', 'clock',
            'original_until', 'received_directory', 'collector_ticket', 'private_modules',
            'module_originals', 'files', '_files_original', 'close_called', 'close_complete',
            'read_ended', 'success', 'failure', 'source_manifest_sha', '_source_manifest_sha_original'))
        self._attributes(value, ('scope', '_scope_original', 'modules', '_modules_original',
            'profile', '_profile_original', 'clock', '_clock_original', 'until', '_until_original',
            'store', '_store_original', 'budget', '_budget_original', 'collector', '_collector_original',
            'snapshot', 'reader_rows', 'status_rows', '_definitions', 'attempted', 'ended',
            'success', 'failure', 'close_attempted', 'close_failure', 'io_started', '_io_started_original'))
        self._attributes(scope.files, ('attempt', 'rows', 'raw', 'pending', 'close_attempted'))
        self._list(scope.files.rows, True)
        self._list(scope.files.raw)
        self._attributes(value.collector, ('_tickets', '_ended', '_pending', '_snapshot', '_rounds'))
        self._list(value.collector._tickets, True)
        self._list(value.collector._rounds)
        self._list(value.reader_rows, True)
        self._list(value.status_rows, True)
        budget, store = value.budget, value.store
        self._attributes(store, ('_resource_budget_v23', '_attempted', '_opened', '_unknown',
            '_marker', '_current_locks', '_proc_reader'))
        self._attributes(budget, ('_store', '_provider', '_readers', '_rows'))
        self._list(budget._rows, True)
        self._list(budget._readers)
        for reader in budget._readers:
            self._attributes(reader, ('_bound_budget_v24', '_resource_budget_v24', '_active',
                '_history_active', '_pending', '_history', '_current_generation', '_issuer'))
            self._list(reader._history)
            for generation in reader._history:
                self._attributes(generation, ('reader', '_issuer', 'ordinal', 'credit', 'budget',
                    'absolute_deadline', 'active', 'ended', 'unknown', 'late', 'observation',
                    'error', 'tickets'))
                self._list(generation.tickets)
                for ticket in generation.tickets:
                    self._attributes(ticket, ('reader', 'generation', '_issuer', 'ordinal', 'credit',
                        'fs', 'path', 'flags', 'creator', 'descriptor', 'open_called', 'returned',
                        'registered', 'failed_without_fd', 'open_error', 'error', 'close_attempted',
                        'close_returned', 'ebadf_observed', 'close_result', 'close_error',
                        'close_readback', 'ebadf_error', 'ebadf_errno', 'unknown'))
        for row in value.status_rows:
            reader, source = row['reader'], row['source']
            self._attributes(reader, ('_source', '_ended', '_pending', '_socket_unknown',
                '_source_unknown', '_receive_unknown', '_socket', '_socket_closed', '_rights', '_sources'))
            self._list(reader._rights, True)
            self._list(reader._sources)
            self._attributes(source, ('_pending', '_consumer', '_reader', '_files', '_actor_calls', '_issued'))
            self._list(source._files)
            self._list(source._actor_calls, True)
            self._list(source._issued)
            for files in source._files:
                self._attributes(files, ('_pending', '_tickets', '_tickets_original', '_io', '_io_original'))
                self._list(files._tickets, True)
        self._startup_verified = True
        self._attributes(owner, ('io', 'original_io', 'boot', 'worker', 'pid', 'clock',
            'original_until', '_startup_namespace_original', '_startup_owner_type_original',
            'startup_called', 'startup_complete', 'startup_failure', 'startup_window_closed',
            '_startup_module_original', '_startup_collect_original', '_startup_collection_type_original',
            '_startup_factory_original', '_startup_window_scope_original', '_startup_window_collection_original'))

    def _probe(self, actor, result, path, args):
        # Do not call _probe_closed/_probe_result: their process.poll is active.
        service = self._service
        if (type(actor) is not dict or actor.get('creator') is not service.capability or
                actor.get('_creator_original') is not service._CAPABILITY_CREATOR or
                service.capability is not service._CAPABILITY_CREATOR or
                actor.get('actors') is not self.probes or actor.get('_actors_original') is not self.probes or
                actor.get('spawn_called') is not True or actor.get('spawn_returned') is not True or
                actor.get('spawn_pending') is not False or actor.get('spawn_unknown') is not False or
                actor.get('communicate_called') is not True or actor.get('communicate_returned') is not True or
                actor.get('closed') is not True or actor.get('failure') is not None or
                actor.get('cleanup_calls') != [] or actor.get('cleanup_failures') != [] or
                actor.get('argv') is not actor.get('_argv_original') or
                actor.get('argv_snapshot') is not actor.get('_argv_snapshot_original') or
                type(actor.get('argv')) is not list or tuple(actor['argv']) != (path,) + args or
                actor.get('argv_snapshot') != (path,) + args or
                actor.get('args_original') is not actor.get('_args_original') or
                actor.get('args_snapshot') is not actor.get('_args_snapshot_original') or
                tuple(actor['args_original']) != args or actor['args_snapshot'] != args or
                actor.get('popen_creator') is not actor.get('_popen_creator_original') or
                actor.get('popen_creator') is not service.subprocess.Popen or
                actor.get('process') is not actor.get('_process_original')):
            _fail('probe_unknown')
        process = actor['process']
        if (type(process) is not service.subprocess.Popen or process.args is not actor['argv'] or
                type(process.returncode) is not int or process.returncode != 0 or actor.get('returncode') != 0 or
                process.stdout is not actor.get('stdout') or process.stderr is not actor.get('stderr') or
                actor.get('stdout') is not actor.get('_stdout_original') or
                actor.get('stderr') is not actor.get('_stderr_original') or
                process.stdout.closed is not True or process.stderr.closed is not True or
                actor.get('out') is not actor.get('_out_original') or type(actor.get('out')) is not bytes or
                len(actor['out']) > 16384 or actor.get('err') is not actor.get('_err_original') or actor.get('err') != b'' or
                actor.get('json_input') is not actor.get('_json_input_original') or
                type(actor.get('json_input')) is not str or actor['out'].decode('utf-8').splitlines() != [actor['json_input']] or
                actor.get('loads_creator') is not service.json.loads or
                actor.get('_loads_creator_original') is not service.json.loads or
                actor.get('snapshot_creator') is not service.json.dumps or
                actor.get('_snapshot_creator_original') is not service.json.dumps or
                type(result) is not dict or result is not actor.get('parsed') or result is not actor.get('_parsed_original') or
                result is not actor.get('returned') or result is not actor.get('_returned_original') or
                actor.get('parsed_snapshot') is not actor.get('_parsed_snapshot_original') or
                service.json.dumps(result, sort_keys=True) != actor.get('parsed_snapshot')):
            _fail('probe_unknown')
        self._mapping(actor)
        self._mapping(result)
        self._list(actor['argv'])
        self._list(actor['args_original'])
        self._list(actor['cleanup_calls'])
        self._list(actor['cleanup_failures'])
        self._attributes(process, ('args', 'returncode', 'stdout', 'stderr'))
        self._attributes(process.stdout, ('closed',))
        self._attributes(process.stderr, ('closed',))

    def _retain_probes_and_assets(self):
        owner, state, ns = self.owner, self.state, self._owner_namespace
        if (type(self.probes) is not list or len(self.probes) != 2 or
                state.probe_actors is not self.probes or state._probe_actors_original is not self.probes or
                state._probe_creator_original is not self._service.capability or
                state.bluetooth_probe_actor is not state._bluetooth_probe_actor_original or
                state.network_probe_actor is not state._network_probe_actor_original or
                self.probes[0] is not state.bluetooth_probe_actor or self.probes[1] is not state.network_probe_actor or
                state.bluetooth_caps is not state._bluetooth_caps_original or
                state.network_caps is not state._network_caps_original or
                state.bluez_path != ns.get('BLUEZ') or state.bluez_path is not state._bluez_path_original or
                state.network_path != ns.get('NETWORK') or state.network_path is not state._network_path_original):
            _fail('probe_unknown')
        # The first two original actors are immutable. The same State may later
        # append its real restoration probes; that does not replace the prefix
        # or release this Gate's claim and does not itself certify RF closure.
        self._probe_prefix = tuple(self.probes)
        self._restore_probes = state.radio_restore_probes
        self._probe(self.probes[0], state.bluetooth_caps, state.bluez_path, ('--capabilities', 'hci0'))
        self._probe(self.probes[1], state.network_caps, state.network_path, ('--capabilities',))
        self._parsed_originals = ((self.probes[0], state.bluetooth_caps),
            (self.probes[1], state.network_caps))
        self._attributes(state, ('probe_actors', '_probe_actors_original', '_probe_creator_original',
            'bluetooth_probe_actor', '_bluetooth_probe_actor_original', 'network_probe_actor',
            '_network_probe_actor_original', 'bluetooth_caps', '_bluetooth_caps_original',
            'network_caps', '_network_caps_original', 'bluez_path', '_bluez_path_original',
            'network_path', '_network_path_original', 'radio_restore_probes'))
        self._probe_verified = True
        self._radio_data = state.bluetooth_caps
        radio = self._modules['mta_receive_radio_baseline']
        try:
            self._radio_original = radio.normalize(self._radio_data)
            self._radio_known = True
        except radio.RadioObservationError:
            self._radio_original = None
        if type(self.assets) is not list or len(self.assets) != 3: _fail('network_spec_unknown')
        self._list(self.assets, True)
        pins = ns.get('HELPER_PINS')
        observer_pin = ns.get('CONNMAN_PIN')
        if type(pins) is not tuple or len(pins) != 2 or type(observer_pin) is not tuple or len(observer_pin) != 2:
            _fail('network_spec_unknown')
        expected = ((ns.get('BLUEZ'), pins[0]), (ns.get('NETWORK'), pins[1]), (ns.get('CONNMAN'), observer_pin))
        for row, pair in zip(self.assets, expected):
            path, pin = pair
            if (type(row) is not dict or type(path) is not str or row.get('path') != path or
                    type(pin) is not tuple or len(pin) != 2 or type(row.get('raw')) is not bytes or
                    len(row['raw']) != pin[0] or hashlib.sha256(row['raw']).hexdigest() != pin[1] or
                    type(row.get('fd')) is not int or row['fd'] < 0 or row.get('attempted') is not True or
                    row.get('closed') is not True or row.get('unknown') is not False or row.get('failure') is not None):
                _fail('network_spec_unknown')
        spec = owner.network_observer_spec
        if (type(spec) is not tuple or spec != (ns.get('CONNMAN'),) + observer_pin or
                spec is not owner._network_observer_spec_original or
                spec is not state._network_observer_spec or spec is not state._network_observer_spec_original or
                owner._network_observer_asset_original is not self.assets[2]):
            _fail('network_spec_unknown')
        self._spec = spec
        self._asset_pins = expected
        self._network_spec_verified = True

    def _retain_barrier(self):
        owner, value, module = self.owner, self.barrier, self._barrier_module
        if (type(value) is not self._barrier_type or value.owner is not owner or value._owner_original is not owner or
                owner.receive_barrier is not value or owner._receive_barrier_original is not value or
                owner._receive_barrier_module_original is not module or owner._receive_barrier_type_original is not self._barrier_type or
                value._host_model_original is not False or value._creator_original is not self._barrier_type or
                type(value._io) is not module._LinuxIo or value._io is not value._io_original or
                value.worker is not self.worker or value.pid != self.pid or value.clock is not self.clock or
                value.until is not self.until or value.namespace is not self._owner_namespace or
                value.owner_type is not self._owner_type or value.attempted is not True or value.ended is not True or
                value.close_called is not True or value.rows is not value._rows_original or
                value.observations is not value._observations_original or value.rounds is not value._rounds_original):
            _fail('barrier_unknown')
        ticket = owner._receive_barrier_ticket
        if (type(ticket) is not dict or ticket.get('creator') is not self._barrier_type or
                ticket.get('partial') is not value or ticket.get('constructor_called') is not True or
                ticket.get('constructed') is not True or ticket.get('returned') is not value or
                ticket.get('ended') is not True or ticket.get('failure') is not None or ticket.get('unknown') is not False):
            _fail('barrier_unknown')
        self._barrier_ticket = ticket
        self._mapping(ticket)
        self._attributes(value, ('owner', '_owner_original', '_io', '_io_original', '_host_model_original',
            '_creator_original', 'worker', 'pid', 'clock', 'until', 'namespace', 'owner_type',
            'attempted', 'ended', 'close_called', 'reason', 'resources_closed', 'rows', '_rows_original',
            'observations', '_observations_original', 'rounds', '_rounds_original', 'failure',
            'failures', '_failures_original', 'close_failures', '_close_failures_original',
            'alias_rows', '_alias_rows_original', 'check', '_check_original', 'check_function'))
        self._list(value.rows, True)
        self._list(value.observations, True)
        self._list(value.rounds, True)
        for row in value.rounds: self._list(row['names'])
        self._list(value.alias_rows, True)
        self._list(value.failures)
        self._list(value.close_failures)
        for row in value.rows:
            if (row.get('owner') is not value or row.get('closed') is not True or row.get('unknown') is not False):
                _fail('barrier_unknown')
            if row.get('open_returned') is True:
                error = row.get('ebadf_error')
                if (row.get('close_attempted') is not True or row.get('close_return') is not None or
                        row.get('close_error') is not None or not isinstance(error, OSError) or
                        type(error.errno) is not int or error.errno != errno.EBADF or
                        type(row.get('fd')) is not int or row['fd'] != row.get('fd_original')):
                    _fail('barrier_unknown')
            elif not (row.get('known_no_fd') is True and row.get('fd') is None and row.get('open_returned') is False):
                _fail('barrier_unknown')
        self._barrier_reason = value.reason if type(value.reason) is str and value.reason in module.REASONS else 'barrier_unknown'
        self._barrier_clear = (value.reason == 'clear' and value.failure is None and
            not value.failures and not value.close_failures and value.resources_closed is True and
            len(value.rows) == 5 and len(value.rounds) == 2 and
            all(row.get('names') == [] and row.get('count') == 0 for row in value.rounds) and
            sum(row.get('kind') == 'stat_pending' and row.get('accepted_absence') is True
                for row in value.observations) == 4)
        if value.reason == 'clear' and not self._barrier_clear:
            self._barrier_reason = 'barrier_unknown'

    def _machine_reason(self):
        if not self.requested: return 'not_requested'
        if not self._startup_verified: return 'startup_unknown'
        if not self._probe_verified: return 'probe_unknown'
        if not self._network_spec_verified: return 'network_spec_unknown'
        if not self._barrier_clear: return self._barrier_reason
        if not self._radio_known: return 'radio_unknown'
        radio = self._radio_data
        if (radio['powered'] is not True or radio['le_enabled'] is not True or
                radio['bredr_enabled'] is not True or
                radio['connectable_advert'] is not True or radio['max_instances'] < 1 or
                radio['max_adv'] < 31 or radio['max_scan'] < 31): return 'radio_unavailable'
        if (radio['connected_devices'] or radio['active_instance_ids'] or
                radio['global_advertising'] is not False or radio['bluez_advertising_active'] is not False or
                radio['discovering'] is not False): return 'radio_busy'
        return 'ready'

    def _originals(self, state, bound):
        # Pure original references and settled inventories only. No nested
        # Owner/State lock, Scope call, new syscall or deadline renewal.
        owner, ns = self.owner, self._owner_namespace
        if (type(self) is not FixedReceiveTrial or self._module is not sys.modules.get('mta_receive_trial') or
                self._module.__dict__ is not self._namespace or self._namespace is not globals() or
                self._module.FixedReceiveTrial is not FixedReceiveTrial or
                self._lock is not self._lock_original or self.owner is not self._owner_original or
                type(owner) is not self._owner_type or ns is not owner._startup_namespace_original or
                ns.get('FixedStateServiceOwner') is not self._owner_type or
                self.state is not self._state_original or state is not self.state or type(state) is not self._state_type or
                self.factory is not self._factory_original or owner.factory is not self.factory or
                self.loader is not self._loader_original or owner.loader is not self.loader or
                self.loader.modules is not self._modules or owner.service is not self._service or
                owner.state is not state or owner._state_original is not state or
                self.scope is not self._scope_original or owner.startup_scope is not self.scope or
                owner._startup_scope_original is not self.scope or self.factory._startup_scope is not self.scope or
                self.collection is not self._collection_original or owner.startup_result is not self.collection or
                self.ticket is not self._ticket_original or self.scope.collector_ticket is not self.ticket or
                self.snapshot is not self._snapshot_original or self.collection.snapshot is not self.snapshot or
                self.received is not self._received_original or owner.received_directory is not self.received or
                owner._received_directory_original is not self.received or
                state._received_binding_original is not self.received or state._original_received_binding is not self.received or
                self.until is not self._until_original or self.until is not owner.original_until or owner.until is not self.until or
                self.loader._original_until is not self.until or state._service_until_original is not self.until or
                state._original_service_until is not self.until or self.received.absolute_until is not self.until or
                self.clock is not self._clock_original or self.clock is not time.monotonic or owner.clock is not self.clock or
                self.received.clock is not self.clock or owner.worker is not self.worker or owner.pid != self.pid or
                self.requested is not self._requested_original or owner.receive_trial_requested is not self.requested or
                owner._receive_trial_requested_original is not self.requested or
                owner.receive_trial is not self or owner._receive_trial_original is not self or
                owner._receive_trial_module_original is not self._module or owner._receive_trial_type_original is not FixedReceiveTrial or
                owner._receive_trial_ticket is not self._owner_ticket or owner._receive_trial_ticket_original is not self._owner_ticket or
                owner.receive_barrier is not self.barrier or owner._receive_barrier_original is not self.barrier or
                self.barrier is not self._barrier_original or owner._receive_barrier_ticket is not self._barrier_ticket or
                self.probes is not self._probes_original or owner.probe_rows is not self.probes or
                self.assets is not self._assets_original or owner.assets is not self.assets or
                owner.network_observer_spec is not self._spec or owner._network_observer_spec_original is not self._spec or
                state._network_observer_spec is not self._spec or state._network_observer_spec_original is not self._spec or
                owner._network_observer_asset_original is not self.assets[2] or
                self._attrs is not self._attrs_original or self._lists is not self._lists_original or
                self._maps is not self._maps_original or self._definitions is not self._definitions_original):
            return False
        ticket = self._owner_ticket
        if (ticket.get('creator') is not FixedReceiveTrial or ticket.get('partial') is not self or
                ticket.get('constructor_called') is not True or ticket.get('constructed') is not True or
                ticket.get('returned') is not self or ticket.get('ended') is not True or
                ticket.get('failure') is not None or ticket.get('unknown') is not False): return False
        if bound and (getattr(state, '_receive_trial', None) is not self or
                      getattr(state, '_receive_trial_original', None) is not self): return False
        inventories = (self._attrs, self._lists, self._maps, self._definitions)
        if (len(self._retention_originals) != 4 or
                any(len(current) != len(originals) or any(a is not b for a, b in zip(current, originals))
                    for current, originals in zip(inventories, self._retention_originals))): return False
        if any(self._modules.get(name) is not module or sys.modules.get(name) is not module for name, module in self._roles):
            return False
        if any(getattr(target, name, None) is not value for target, name, value in self._definitions): return False
        if (self.scope.private_modules is not self._private or len(self._private) != len(self._private_rows) or
                any(self._private.get(name) is not module for name, module in self._private_rows)): return False
        definitions = self._collection_type._definitions_now(self.collection)
        if len(definitions) != len(self.collection._definitions) or any(
                a is not b for a, b in zip(definitions, self.collection._definitions)): return False
        # Result dictionaries include mutable lists. Identity alone must never
        # let an initially busy/unknown observation be edited into readiness.
        if any(self._service.json.dumps(result, sort_keys=True) != actor['parsed_snapshot']
                for actor, result in self._parsed_originals): return False
        if (type(self.probes) is not list or not 2 <= len(self.probes) <= MAX_LIST or
                any(a is not b for a, b in zip(self.probes[:2], self._probe_prefix)) or
                state.radio_restore_probes is not self._restore_probes): return False
        for actor in self.probes[2:]:
            if (type(actor) is not dict or actor.get('creator') is not self._service.capability or
                    actor.get('_creator_original') is not self._service.capability or
                    actor.get('actors') is not self.probes or actor.get('_actors_original') is not self.probes or
                    not any(type(row) is dict and row.get('creator') is self._service.capability and
                        row.get('actors') is self.probes and row.get('before_actor') is self._probe_prefix[0] and
                        row.get('before') is self._parsed_originals[0][1] and row.get('current_actor') is actor
                        for row in self._restore_probes)):
                return False
        for target, values in self._attrs:
            if any(getattr(target, name, None) is not value for name, value in values): return False
        for value, originals in self._lists:
            if len(value) != len(originals) or any(a is not b for a, b in zip(value, originals)): return False
        for value, keys, originals in self._maps:
            if tuple(sorted(value)) != keys or any(value.get(key) is not original for key, original in originals): return False
        return True

    def binds(self, state):
        """Pure canonical binding check; permits the State's initial bind only."""
        try:
            with self._lock:
                return self._originals(state, False)
        except BaseException: return False

    def _live(self):
        now = self._clock_original()
        if (not _finite(now) or self._last is not None and now < self._last or now >= self.until):
            self.expired = self.revoked = True
            if self.revoke_reason is None: self.revoke_reason = 'expired'
            self.reason = 'expired'
            return False
        self._last = now
        return True

    def _idle(self, state):
        return (state.state == 'idle' and state.operation is None and state.session is None and
                state.worker is None and state.native_epoch == self._epoch and
                state.closing is False and state.wifi_restore_pending is False and state.radio_restore_pending is False and
                self.owner.stop_called is False and self.owner.close_called is False and
                self.owner.start_complete is True and self._owner_ticket.get('bind_called') is True and
                self._owner_ticket.get('bind_returned') is self)

    def _own_radio_pending(self, state, op, session):
        if state.radio_restore_pending is False: return True
        if state.radio_restore_pending is not True: return False
        helper, bridge, handoff = op.helper, op.client_bridge, op.client_handoff
        ticket = op.receive_bridge_ticket
        return (type(helper) is self._service.PrivateHelper and state.helper is helper and
            helper.path == state.bluez_path and helper.spawn_resolved is True and helper.spawn_unknown is False and
            type(bridge) is self._service.StateClientBridge and bridge.state is state and
            bridge.operation is op and bridge.session is session and bridge.worker is session._worker and
            bridge.epoch == op.epoch and bridge.cancelled is op.cancelled and bridge._factory is self.factory and
            type(handoff) is self._service.ReceiveConnectHandoff and bridge.handoff is handoff and
            handoff.state is state and handoff.operation is op and handoff.session is session and
            handoff.worker is session._worker and handoff.helper is helper and
            type(ticket) is dict and ticket.get('started') is True and ticket.get('returned') is bridge and
            op.actor_unknown is False)

    def available(self, state):
        try:
            with self._lock:
                if not self._originals(state, True): self.reason = 'source_changed'; return False
                if self.revoked: self.reason = self.revoke_reason or 'revoked'; return False
                if not self._live(): return False
                if self.claim_count: self.reason = 'claimed'; return False
                reason = self._machine_reason()
                if reason != 'ready': self.reason = reason; return False
                if not self._idle(state): self.reason = 'state_not_idle'; return False
                self.reason = 'ready'
                return True
        except BaseException as error:
            if self.failure is None: self.failure = error
            self.reason = 'owner_context'
            return False

    def claim(self, state, op):
        with self._lock:
            if not self._originals(state, True): _fail('source_changed')
            if self.claim_count or self.claimed_operation is not None: _fail('already_claimed')
            if self.revoked or not self._live() or self._machine_reason() != 'ready': _fail(self.reason)
            if (type(op) is not self._operation_type or state.operation is not op or op.kind != 'receive' or
                    type(op.epoch) is not int or op.epoch != self._epoch + 1 or state.native_epoch != op.epoch or
                    op.backend is not None or op.consent is not True or op.receive_factory is not self.factory or
                    op.receive_network_spec is not self._spec or op.receive_network_clock is not self.clock or
                    op.receive_network_until is not state._service_cleanup_until_original or
                    getattr(op, 'receive_trial', None) is not self or getattr(op, '_receive_trial_original', None) is not self or
                    type(op.cancelled) is not threading.Event or op.cancelled.is_set() or
                    state.closing is not False or self.owner.stop_called is not False or self.owner.close_called is not False or
                    state.wifi_restore_pending is not False or state.radio_restore_pending is not False):
                _fail('claim_changed')
            # Retain the claim before Session.__new__/__init__/start. No failure
            # or cancellation can release it or make a second trial available.
            self.claimed_operation = self._claimed_operation_original = op
            self._claim_originals = (op, op.epoch, op.cancelled, op.receive_factory,
                op.receive_network_spec, op.receive_network_clock, op.receive_network_until)
            self.claim_count = 1
            self.reason = 'claimed'
            return op

    def _claim_matches(self, state, op):
        originals = self._claim_originals
        return (self.claim_count == 1 and type(originals) is tuple and len(originals) == 7 and
            op is self.claimed_operation and op is self._claimed_operation_original and op is originals[0] and
            type(op) is self._operation_type and op.kind == 'receive' and op.epoch is originals[1] and
            state.native_epoch == op.epoch and state.operation is op and op.cancelled is originals[2] and
            op.receive_factory is originals[3] and op.receive_network_spec is originals[4] and
            op.receive_network_clock is originals[5] and op.receive_network_until is originals[6] and
            getattr(op, 'receive_trial', None) is self and getattr(op, '_receive_trial_original', None) is self)

    def attach_session(self, state, op, session):
        with self._lock:
            if not self._originals(state, True) or not self._claim_matches(state, op): _fail('claim_changed')
            if self.session is not None or self._session_originals is not None: _fail('session_unknown')
            ticket = getattr(op, 'receive_session_ticket', None)
            restore, extra, task = getattr(session, '_restore', None), getattr(session, '_extra', None), getattr(session, '_task', None)
            cells = tuple(cell.cell_contents for cell in task.__closure__) if type(task) is types.FunctionType and task.__closure__ else ()
            if (type(session) is not self._session_type or session is not op.session or state.session is not session or
                    type(ticket) is not dict or ticket is not getattr(op, '_receive_session_ticket_original', None) or
                    ticket.get('creator') is not self._session_type or ticket.get('initializer') is not self._session_init or
                    ticket.get('namespace') is not self._session_module.__dict__ or
                    ticket.get('new_called') is not True or ticket.get('new_returned') is not True or
                    ticket.get('value_original') is not session or ticket.get('init_called') is not True or
                    ticket.get('init_returned') is not True or ticket.get('init_error') is not None or
                    ticket.get('attach_called') is not True or ticket.get('attach_returned') is not False or
                    ticket.get('attach_error') is not None or
                    not _same_method(restore, state, self._state_type._restore_owner) or
                    not _same_method(extra, state, self._state_type._close_extra) or
                    type(task) is not types.FunctionType or task.__globals__ is not self._service.__dict__ or
                    task.__code__ not in self._state_type._new_operation_locked.__code__.co_consts or
                    len(cells) != 2 or not any(value is state for value in cells) or not any(value is op for value in cells) or
                    session._lease_owner is not op or session.cancelled is not op.cancelled or state.cancelled is not op.cancelled or
                    session._absolute_until is not self.until or session._absolute_until_original is not self.until or
                    session._direction != 'receive' or session._scoped_owner is not None or session._release is not None or
                    session._started is not False or session._worker_start_claimed is not False or
                    type(session._worker) is not threading.Thread or state.worker is not session._worker):
                _fail('session_unknown')
            self.session = self._session_original = session
            self._session_originals = (session, ticket, session._worker, session.cancelled, task, restore,
                extra, session._lease_owner, session._absolute_until_original)
            return session

    def _session_matches(self, state, op, session):
        refs = self._session_originals
        if type(refs) is not tuple or len(refs) != 9: return False
        ticket = refs[1]
        return (session is self.session and session is self._session_original and session is refs[0] and
            type(session) is self._session_type and op.session is session and state.session is session and
            op.receive_session_ticket is ticket and op._receive_session_ticket_original is ticket and
            ticket.get('creator') is self._session_type and ticket.get('initializer') is self._session_init and
            ticket.get('value_original') is session and ticket.get('init_returned') is True and ticket.get('init_error') is None and
            ticket.get('attach_called') is True and ticket.get('attach_returned') is True and ticket.get('attach_error') is None and
            session._worker is refs[2] and state.worker is refs[2] and session.cancelled is refs[3] and
            session._task is refs[4] and session._restore is refs[5] and session._extra is refs[6] and
            session._lease_owner is refs[7] and session._absolute_until is refs[8] and
            session._absolute_until_original is refs[8] and refs[8] is self.until)

    def allows(self, state, op, session):
        try:
            with self._lock:
                if (not self._originals(state, True) or not self._claim_matches(state, op) or
                        not self._session_matches(state, op, session) or self.revoked or
                        self._machine_reason() != 'ready' or not self._live()): return False
                return (threading.current_thread() is self._session_originals[2] and
                    session._started is True and session._worker_start_resolved is True and
                    session._worker_start_unknown is False and _finite(session._task_deadline) and
                    session._task_deadline <= self.until and self.clock() < session._task_deadline and
                    not op.cancelled.is_set() and state.closing is False and
                    self.owner.stop_called is False and self.owner.close_called is False and
                    state.wifi_restore_pending is False and self._own_radio_pending(state, op, session))
        except BaseException as error:
            if self.failure is None: self.failure = error
            return False

    def _handoff_matches(self, state, op, session, handoff, role):
        """Pure original constructor/actor inventory; never a radio allowance."""
        ticket = getattr(op, 'receive_handoff_ticket', None)
        originals = ticket.get('originals') if type(ticket) is dict else None
        if (type(ticket) is not dict or ticket is not getattr(op, '_receive_handoff_ticket_original', None) or
                set(ticket) != {'creator', 'initializer', 'namespace', 'new_called', 'new_returned',
                    'value_original', 'init_called', 'init_returned', 'init_error', 'originals'} or
                ticket.get('creator') is not self._handoff_type or ticket.get('initializer') is not self._handoff_init or
                ticket.get('namespace') is not self._handoff_module.__dict__ or
                getattr(self._handoff_init, '__globals__', None) is not self._handoff_module.__dict__ or
                ticket.get('new_called') is not True or ticket.get('new_returned') is not True or
                ticket.get('value_original') is not handoff or ticket.get('init_called') is not True or
                type(ticket.get('init_returned')) is not bool or ticket.get('init_error') is not None or
                type(handoff) is not self._handoff_type or op.client_handoff is not handoff or
                getattr(handoff, '_data_ticket_original', None) is not ticket or
                type(originals) is not tuple or len(originals) != 9): return False
        helper, key, crypto, worker, reader, task_until = originals[2:8]
        if (originals[0] is not op or originals[1] is not session or originals[8] is not self or
                type(helper) is not self._service.PrivateHelper or op.helper is not helper or state.helper is not helper or
                helper.path != state.bluez_path or helper.spawn_resolved is not True or helper.spawn_unknown is not False or
                helper.closed is not False or type(reader) is not threading.Thread or helper.thread is not reader or
                type(crypto) is not self._crypto_type or op.crypto is not crypto or state.crypto is not crypto or
                type(key) is not self._key_type or op.key is not key or state.key is not key or
                key.closed is not False or key._owner is not crypto._lib or
                worker is not session._worker or worker is not self._session_originals[2] or
                session._task_deadline is not task_until or not _finite(task_until) or task_until > self.until or
                handoff.state is not state or handoff.operation is not op or handoff.session is not session or
                handoff.helper is not helper or handoff.key is not key or handoff.crypto is not crypto or
                handoff.worker is not worker or handoff.reader is not reader or handoff.epoch != op.epoch or
                handoff.clock is not self._clock_original or handoff.deadline is not task_until or
                handoff.deadline is not getattr(handoff, '_deadline_original', None) or
                handoff._cancelled is not False or handoff._failed is not False or op.actor_unknown is not False):
            return False
        current = threading.current_thread()
        if role == 'capture':
            if ticket['init_returned'] is not True or current is not reader: return False
        elif role == 'worker':
            if current is not worker: return False
            # An unfinished ctor is recognized only while the original worker
            # executes that exact initializer. No reader or later work uses it.
            if ticket['init_returned'] is False and (handoff._received or handoff._decrypt_attempted or handoff._claimed):
                return False
        else: return False
        # Current receive's pending network state is not permission to create
        # another task. Only the exact running Bridge may continue DATA checks
        # on its captured Handoff while it owns Parent/F publication/CONNECT.
        if state.wifi_restore_pending is True:
            bridge = op.client_bridge; bridge_ticket = op.receive_bridge_ticket
            if (role != 'worker' or ticket['init_returned'] is not True or handoff._received is not True or
                    type(bridge) is not self._service.StateClientBridge or bridge.state is not state or
                    bridge.operation is not op or bridge.session is not session or bridge.worker is not worker or
                    bridge.handoff is not handoff or bridge.cancelled is not op.cancelled or
                    bridge._factory is not self.factory or bridge.started is not True or bridge.running is not True or
                    type(bridge_ticket) is not dict or bridge_ticket.get('started') is not True or
                    bridge_ticket.get('returned') is not bridge): return False
        elif state.wifi_restore_pending is not False: return False
        return type(state.radio_restore_pending) is bool

    def allows_handoff_data(self, state, op, session, handoff, role):
        """Only original claimed Handoff DATA; no FS, IO, RF or renewed period."""
        try:
            with self._lock:
                if (not self._originals(state, True) or not self._claim_matches(state, op) or
                        not self._session_matches(state, op, session) or self.revoked or
                        self._machine_reason() != 'ready' or not self._live() or
                        not self._handoff_matches(state, op, session, handoff, role)): return False
                return (session._started is True and session._worker_start_resolved is True and
                    session._worker_start_unknown is False and self.clock() < session._task_deadline and
                    not op.cancelled.is_set() and state.closing is False and
                    self.owner.stop_called is False and self.owner.close_called is False)
        except BaseException as error:
            if self.failure is None: self.failure = error
            return False

    def revoke(self, state, reason):
        # Called before Owner stop/close flags, cancellation or finalization.
        # No clock or cleanup permission check may prevent revocation.
        try:
            with self._lock:
                if not self._originals(state, True) or type(reason) is not str or reason not in REVOKE_REASONS:
                    return False
                self.revoked = True
                if reason == 'expired': self.expired = True
                if self.revoke_reason is None: self.revoke_reason = reason
                self.reason = self.revoke_reason
                return True
        except BaseException: return False

    def closed(self, state):
        """Gate revocation/inventory only; not Session or RF restoration."""
        try:
            with self._lock:
                if not self.revoked or not self._originals(state, True): return False
                if self.claim_count == 0:
                    return (self.claimed_operation is None and self._claimed_operation_original is None and
                        self.session is None and self._session_original is None and
                        self._claim_originals is None and self._session_originals is None)
                if not self._claim_matches(state, self.claimed_operation): return False
                # A retained claimed partial constructor is not a Gate leak.
                # State/Owner must independently refuse to sign its Session.
                if self.session is None:
                    return self._session_original is None and self._session_originals is None
                return self._session_matches(state, self.claimed_operation, self.session)
        except BaseException: return False

    def public_facts(self):
        """Finite private-state projection; no raw observation or identifiers."""
        available = self.available(self.state)
        with self._lock:
            return {'reason': self.reason if self.reason in REASONS else 'owner_context',
                'requested': self.requested is True, 'available': available is True,
                'claimed': self.claim_count == 1, 'claim_count': 1 if self.claim_count == 1 else 0,
                'session_attached': self.session is not None, 'revoked': self.revoked is True,
                'expired': self.expired is True, 'startup_verified': self._startup_verified is True,
                'probe_verified': self._probe_verified is True, 'radio_known': self._radio_known is True,
                'barrier_clear': self._barrier_clear is True,
                'network_spec_verified': self._network_spec_verified is True,
                'restoration_verified': False, 'phone_verified': False}
