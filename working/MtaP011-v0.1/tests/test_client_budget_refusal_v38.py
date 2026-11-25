"""One unique v38 HOST native refusal/prescreen/known-cleanup boundary.

Native Store acquire/first commit/current, Pending actual ProcReader.reserve,
Coord error propagation and cleanup fresh reads/CAS run on explicit FakeIO and
FakeFs models. Fixed native accounting reserve calls consume original available
PROC_GENERATION credits; counts/limits are never rewritten or increased. This
does not execute F, Parent, State, transfer, RF, device, phone or full restore.
Direct diagnostic consumers and negative scope/worker fields are explicit HOST
unit seams. No refusal returns an observation, ready fact or network permission.
Old TestCase methods remain unselected and no previous passed method is rerun.
A post-open content failure keeps semantic identity unknown while its original
native descriptor inventory may be known closed; this is not a CloseProof.
Only Pending changes from the frozen v36-r2 graph. All earlier native refusal,
FILES, replay, cleanup and post-IO unknown assertions remain in this new method.
Delegated numeric call observations add possible-refusal cost boundaries:
normal sufficient reads skip full historical capture; actual native count and
payload refusals still capture exact originals; cancelled network refusal does
not become safe exhaustion. Malformed/profile/lock probes are denial-only
helper inputs, not simulated observation/ready/permit or prior-error clearing.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib
import json
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
PLAN = 'host/client_budget_refusal_v38_source_manifest.json'
PLAN_SHA = '2259ad87bce14f17ecd74f670dacbafa53d00fff67eddad2ae1538a906ec2423'
PLAN_BYTES = 8080
PREVIOUS_PLAN_SHA = '676d2058feb1b2fc94aa1a686b7a8a2b42475dfff3028eec3ab05e0647079e29'
# Read the frozen old wrapper's literal definition inventory, never import or
# run it. Its transitive helpers only define synthetic IO/records here.
DEPENDENCY_PLAN = 'host/client_receive_executor_v32_check.py'
DEPENDENCY_PLAN_SHA = 'dbaac6524147818b763f78f234c87793e7bada5a4759a0ac90828c41ccdc348f'
DEPENDENCY_PLAN_BYTES = 24766
EXTRA_INPUTS = ()


def fixed(path, digest, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed input changed')
    return raw


def inputs_and_fixture_definitions():
    plan = json.loads(fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if (set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or
            plan['schema'] != 'client-budget-refusal-v38-host' or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA):
        raise ValueError('HOST cap graph changed')
    rows = plan['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST cap graph changed')
    inputs = [(row['module'], fixed(row['path'], row['sha256'], row['bytes'])) for row in rows]
    extras = [(name, fixed(path, digest, size)) for name, path, digest, size in EXTRA_INPUTS]
    tree = ast.parse(fixed(DEPENDENCY_PLAN, DEPENDENCY_PLAN_SHA, DEPENDENCY_PLAN_BYTES))
    inventories = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'FIXTURE_INPUTS' for target in node.targets)]
    if len(inventories) != 1 or len(inventories[0]) != 70:
        raise ValueError('HOST fixture inventory changed')
    for path, digest, size in inventories[0]: fixed(path, digest, size)
    # Definitions only; these old modules may initialize private legacy types,
    # but neither make_full nor an old TestCase method is called.
    full = importlib.import_module('test_client_full_lifecycle_v24')
    importlib.import_module('test_client_durable_connect_v19')
    importlib.import_module('test_client_proc')
    importlib.import_module('test_client_process_owner')
    return inputs, extras, full


def private_domain(inputs, extras):
    modules, actual_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private cap definition unavailable')
            return modules[name]
        return actual_import(name, *args, **kwargs)
    for name, raw in inputs + extras:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if name == 'HOST_Operation':
            selected = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Operation']
            if len(selected) != 1: raise ValueError('HOST Operation definition changed')
            module = types.ModuleType(name)
            module.threading = threading
            modules[name] = module
            # Only the pinned native Operation ClassDef: do not import State or
            # activate its admission/startup helpers.
            exec(compile(ast.Module(body=selected, type_ignores=[]), 'HOST-pinned-Operation', 'exec'), module.__dict__)
            continue
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-budget-refusal-v38/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(name for name, unused in inputs) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST cap module order changed')
    return modules


def forbidden_platform(stack):
    # No actual worker, process, platform-file, crypto or network/RF IO runs.
    for target in ('socket.socket', 'socket.create_connection', 'subprocess.Popen', 'ctypes.CDLL',
            'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat', 'os.stat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.getpid', 'os.fork', 'os.execve', 'os.kill',
            'os.waitpid', 'os.system', 'os.urandom', 'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(target, side_effect=AssertionError('actual platform forbidden'), create=True))


class BudgetRefusalV38Tests(unittest.TestCase):
    def test_native_prescreen_count_payload_cancelled_denials_preserve_known_cleanup(self):
        inputs, extras, full = inputs_and_fixture_definitions()
        with ExitStack() as stack:
            forbidden_platform(stack)
            modules = private_domain(inputs, extras)
        fixture, proc_helpers, unused_owner_helpers = full.setup_definitions(modules)
        core, stores, proc, budgets, pending, coord = (modules[name] for name in
            ('mta_p2p_client_init', 'mta_client_store', 'mta_client_proc',
             'mta_client_resource_budget', 'mta_client_pending', 'mta_client_coordination'))
        identity = core.Identity('a' * 64)
        # Counters delegate original functions and retain exceptions only in
        # private HOST memory. No history traversal or native error is replaced.
        observations = {}
        def costs(marker):
            return observations.setdefault(marker, {'possible_calls': 0, 'possible_true': 0,
                'possible_false': 0, 'owner_calls': 0, 'reader_facts_calls': 0,
                'accounting_facts_calls': 0, 'errors': []})
        actual_possible = pending.ClientPendingMarker._refusal_possible_v38
        actual_owner = pending.ClientPendingMarker._refusal_owner_v36
        actual_reader_facts = pending.ClientPendingMarker._refusal_reader_facts_v36
        actual_accounting_facts = pending.ClientPendingMarker._refusal_accounting_facts_v36
        actual_observe = pending.ClientPendingMarker._observe_self
        def observe_possible(marker, reader, budget, context):
            row = costs(marker); row['possible_calls'] += 1
            value = actual_possible(marker, reader, budget, context)
            if value is True: row['possible_true'] += 1
            elif value is False: row['possible_false'] += 1
            return value
        def observe_owner(marker, reader, budget, context):
            costs(marker)['owner_calls'] += 1
            return actual_owner(marker, reader, budget, context)
        def observe_reader_facts(marker, reader):
            costs(marker)['reader_facts_calls'] += 1
            return actual_reader_facts(marker, reader)
        def observe_accounting_facts(marker, budget):
            costs(marker)['accounting_facts_calls'] += 1
            return actual_accounting_facts(marker, budget)
        def observe_self(marker):
            try: return actual_observe(marker)
            except BaseException as error:
                costs(marker)['errors'].append(error)
                raise

        def make_store():
            io, fs = fixture.Io(), proc_helpers.FakeFs()
            store = stores.DurableClientInitStore(fixture.old.TOKEN, identity,
                _coordination_io=io, _files_io=io, _pending_io=io,
                _proc_reader=proc.ProcReader(_fs=fs, _clock=io.clock), _clock=io.clock)
            locks = store.acquire(identity, io.clock() + 3.0)
            issued = float(io.clock())
            record = store.commit(locks, core.Journal(identity, 'prepared', fixture.baseline(),
                issued + 20.0, session_profile='trial20', issued_at=issued))
            return store, locks, record, io, fs

        def consume_original_available_generations(store):
            budget = store._resource_budget_v23
            column = budgets.KINDS.index('PROC_GENERATION')
            limit = budget._profile.count_limit(budgets.PREPARATION_NETWORK, 'PROC_GENERATION')
            remaining = limit - budget._used[0][column]
            before_limit = budget._profile.counts
            for unused in range(remaining):
                # Actual native accounting operation, not a fake generation,
                # altered quota/count or started resource. No payload is lent.
                budget.reserve(budgets.PREPARATION_NETWORK, 'PROC_GENERATION')
            self.assertIs(before_limit, budget._profile.counts)
            self.assertEqual(limit, budget._used[0][column])
            self.assertEqual(0, budget.status()['active_producers'])
            self.assertFalse(budget.status()['resource_pending'])
            return budget

        def fail_binding(store, consumer):
            with store._mutex:
                try: store._binding.verify(consumer, store._epoch)
                except budgets.ResourceBudgetError as error:
                    self.assertEqual('safe_exhaustion', error.code)
                    return error
            self.fail('native denied generation unexpectedly returned observation')

        def deny_business(store, callback):
            try: callback()
            except stores.DurableStoreError as error:
                self.assertEqual('component_error', error.code)
                self.assertTrue(store._unknown)
                return error
            self.fail('foreign or unknown refusal unexpectedly succeeded')

        with ExitStack() as stack:
            forbidden_platform(stack)
            stack.enter_context(mock.patch.object(pending.ClientPendingMarker, '_refusal_possible_v38', observe_possible))
            stack.enter_context(mock.patch.object(pending.ClientPendingMarker, '_refusal_owner_v36', observe_owner))
            stack.enter_context(mock.patch.object(pending.ClientPendingMarker, '_refusal_reader_facts_v36', observe_reader_facts))
            stack.enter_context(mock.patch.object(pending.ClientPendingMarker, '_refusal_accounting_facts_v36', observe_accounting_facts))
            stack.enter_context(mock.patch.object(pending.ClientPendingMarker, '_observe_self', observe_self))
            # Normal current calls keep original native checks but must not
            # traverse historical denial facts when actual reserves fit.
            steady, steady_locks, steady_record, unused_io, unused_fs = make_store()
            try:
                before = dict(costs(steady._marker))
                value = steady.current(steady_locks)
                after = costs(steady._marker)
                self.assertTrue(core._same_journal(value, steady_record))
                self.assertGreater(after['possible_calls'], before['possible_calls'])
                self.assertEqual(after['possible_calls'] - before['possible_calls'],
                    after['possible_false'] - before['possible_false'])
                for key in ('possible_true', 'owner_calls', 'reader_facts_calls', 'accounting_facts_calls'):
                    self.assertEqual(after[key], before[key])
                self.assertFalse(steady._unknown)
                self.assertFalse(steady._marker._binding_ticket.unknown)
            finally: steady.close()
            # The positive path enters actual Store.current through Coord.
            store, locks, record, io, fs = make_store()
            try:
                budget = consume_original_available_generations(store)
                history, opens, fs_ops = tuple(store._proc_reader._history), tuple(fs.opens), tuple(fs.operations)
                canonical, issuance = store._canonical, store._session_issued_v28
                observed = store._binding_observation
                counts, payload = budget.status()['counts'], budget.status()['retained_payload_bytes']
                with self.assertRaises(budgets.ResourceBudgetError) as failure:
                    store.current(locks)
                error, row = failure.exception, store._marker._binding_refusal_v36
                self.assertIs(row.error, error)
                native_costs = costs(store._marker)
                self.assertGreater(native_costs['possible_true'], 0)
                self.assertGreater(native_costs['owner_calls'], 0)
                self.assertGreater(native_costs['reader_facts_calls'], 0)
                self.assertGreater(native_costs['accounting_facts_calls'], 0)
                self.assertIs(row.consumer, store._coordination)
                self.assertIs(row.reader, store._proc_reader)
                self.assertIs(row.budget, budget)
                self.assertIs(row.budget_mutex, store._mutex)
                self.assertIs(row.budget_epoch, store._epoch)
                self.assertTrue(row.ended); self.assertTrue(row.coord_seen); self.assertTrue(row.store_seen)
                self.assertFalse(store._unknown)
                self.assertTrue(store._marker._binding_ticket.ready)
                self.assertFalse(store._marker._binding_ticket.unknown)
                self.assertIs(canonical, store._canonical)
                self.assertIs(issuance, store._session_issued_v28)
                self.assertIs(observed, store._binding_observation)  # No new observation on refusal.
                self.assertEqual(history, tuple(store._proc_reader._history))
                self.assertEqual(opens, tuple(fs.opens)); self.assertEqual(fs_ops, tuple(fs.operations))
                self.assertEqual(counts, budget.status()['counts'])
                self.assertEqual(payload, budget.status()['retained_payload_bytes'])
                self.assertTrue(store._proc_reader.history_closed())
                self.assertFalse(budget.status()['network_authorized'])
                with store._mutex:
                    self.assertFalse(store._marker._consume_refusal_coord_v36(error, store._coordination, store._epoch))
                    self.assertFalse(store._marker._consume_refusal_store_v36(error, store))
                # A second real denial is a fresh original, never an old permit.
                second = fail_binding(store, store._coordination)
                second_row = store._marker._binding_refusal_v36
                self.assertIsNot(second, error); self.assertIsNot(second_row, row)
                with store._mutex:
                    self.assertFalse(store._marker._consume_refusal_store_v36(error, store))
                    with self.assertRaises(budgets.ResourceBudgetError) as forwarded:
                        store._coordination._report(second)
                    self.assertIs(second, forwarded.exception)
                    with self.assertRaises(budgets.ResourceBudgetError) as forwarded:
                        store._report(second)
                    self.assertIs(second, forwarded.exception)
                    self.assertFalse(store._marker._consume_refusal_store_v36(second, store))
                # Independent original CLEANUP credits enable actual fresh
                # observations; the exhausted network ledger never renews.
                network_before = budget.status()['counts'][0]
                original_until = record.deadline
                budget.cancel(); store._resource_lane_v23 = budgets.CLEANUP
                store._recovery_deadline = io.clock() + 60.0
                reread = store.current(locks)
                self.assertTrue(core._same_journal(reread, record))
                self.assertGreater(len(store._proc_reader._history), len(history))
                cleaned = store.commit(locks, reread.replace(stage='cleanup_intent'))
                verified = store.commit(locks, cleaned.replace(stage='cleanup_verified'))
                self.assertEqual(original_until, verified.deadline)
                self.assertIs(issuance, store._session_issued_v28)
                self.assertEqual(network_before, budget.status()['counts'][0])
                self.assertGreater(budget.status()['counts'][1][budgets.KINDS.index('PROC_GENERATION')], 0)
                self.assertFalse(store._unknown)
                self.assertFalse(store._restore_verified)
                self.assertIsNone(store._finish_receipt)
            finally: store.close()  # Local modeled FDs only; not marker clear or restore.

            # The unchanged actual FILES read_current directly propagates the
            # original error; no Coord consumption is required on this path.
            direct, direct_locks, unused_record, unused_io, unused_fs = make_store()
            try:
                consume_original_available_generations(direct)
                with direct._mutex:
                    with self.assertRaises(budgets.ResourceBudgetError) as failure:
                        direct._files.read_current()
                    original = failure.exception
                    row = direct._marker._binding_refusal_v36
                    self.assertIs(row.consumer, direct._files)
                    self.assertFalse(row.coord_seen)
                    with self.assertRaises(budgets.ResourceBudgetError) as forwarded:
                        direct._report(original)
                    self.assertIs(original, forwarded.exception)
                    self.assertTrue(row.store_seen); self.assertFalse(direct._unknown)
            finally: direct.close()

            # A count still below its fixed limit can refuse only because the
            # actual next maximum payload would exceed its original byte cap.
            payload_store, payload_locks, unused_record, unused_io, payload_fs = make_store()
            try:
                budget = payload_store._resource_budget_v23
                column = budgets.KINDS.index('PROC_GENERATION')
                remaining = budgets._PAYLOAD_BYTES[0] - budget._retained[0] - budget._inflight[0]
                maximum = remaining - proc.MAX_GENERATION_PAYLOAD + 1
                self.assertGreater(maximum, 0)
                credit = budget.reserve(budgets.PREPARATION_NETWORK, 'FILES_OPEN', maximum)
                self.assertIs(budget._owned(credit)['credit'], credit)
                self.assertFalse(budget._owned(credit)['started'])
                self.assertFalse(budget._owned(credit)['unknown'])
                self.assertLess(budget._used[0][column], budgets._COUNTS[0][column])
                self.assertGreater(budget._retained[0] + budget._inflight[0] +
                    proc.MAX_GENERATION_PAYLOAD, budgets._PAYLOAD_BYTES[0])
                history, opens, canonical = (tuple(payload_store._proc_reader._history),
                    tuple(payload_fs.opens), payload_store._canonical)
                accounting = budget.status()
                with self.assertRaises(budgets.ResourceBudgetError) as failure:
                    payload_store.current(payload_locks)
                error, row = failure.exception, payload_store._marker._binding_refusal_v36
                self.assertEqual('safe_exhaustion', error.code)
                self.assertIs(row.error, error)
                self.assertTrue(row.coord_seen); self.assertTrue(row.store_seen)
                self.assertFalse(payload_store._unknown)
                self.assertFalse(payload_store._marker._binding_ticket.unknown)
                self.assertIs(payload_store._canonical, canonical)
                self.assertEqual(tuple(payload_store._proc_reader._history), history)
                self.assertEqual(tuple(payload_fs.opens), opens)
                self.assertEqual(budget.status()['counts'], accounting['counts'])
                self.assertEqual(budget.status()['inflight_payload_bytes'], accounting['inflight_payload_bytes'])
                self.assertTrue(payload_store._proc_reader.history_closed())
                self.assertGreater(costs(payload_store._marker)['possible_true'], 0)
                self.assertGreater(costs(payload_store._marker)['reader_facts_calls'], 0)
                self.assertFalse(budget.status()['network_authorized'])
            finally: payload_store.close()
            # Native reserve checks cancellation BEFORE full count/payload.
            # A stop is not converted into known safe refusal or new readiness.
            cancelled, cancel_locks, unused_record, unused_io, cancel_fs = make_store()
            try:
                budget = consume_original_available_generations(cancelled)
                budget.cancel()
                before = dict(costs(cancelled._marker))
                history, opens = tuple(cancelled._proc_reader._history), tuple(cancel_fs.opens)
                deny_business(cancelled, lambda: cancelled.current(cancel_locks))
                after = costs(cancelled._marker)
                error = after['errors'][-1]
                self.assertIs(type(error), budgets.ResourceBudgetError)
                self.assertEqual('network_cancelled', error.code)
                self.assertGreater(after['possible_false'], before['possible_false'])
                for key in ('possible_true', 'owner_calls', 'reader_facts_calls', 'accounting_facts_calls'):
                    self.assertEqual(after[key], before[key])
                self.assertIsNone(cancelled._marker._binding_refusal_v36)
                self.assertEqual(tuple(cancelled._proc_reader._history), history)
                self.assertEqual(tuple(cancel_fs.opens), opens)
                self.assertTrue(cancelled._marker._binding_ticket.unknown)
                self.assertFalse(cancelled._marker._binding_ticket.ready)
                self.assertTrue(cancelled._unknown)
                self.assertFalse(any(budget.status()['safe_exhaustion']))
            finally: cancelled.close()
            # Denial-only malformed/lock/profile inputs. These probes call the
            # pure helper, NOT a read/reserve or a fabricated refusal issuer.
            # The recycled tuple is explicitly not a current binding operation.
            probe, unused_locks, unused_record, unused_io, probe_fs = make_store()
            try:
                budget = consume_original_available_generations(probe)
                marker, reader = probe._marker, probe._proc_reader
                context = (probe._binding, probe._coordination, probe._epoch, marker._binding_call_v36)
                history, opens, native_count = tuple(reader._history), tuple(probe_fs.opens), budget.status()['counts']
                before = dict(costs(marker))
                self.assertFalse(marker._refusal_possible_v38(reader, budget, context))  # Mutex NOT held.
                with probe._mutex:
                    for malformed in (None, (), context[:3], list(context)):
                        self.assertFalse(marker._refusal_possible_v38(reader, budget, malformed))
                    with mock.patch.object(budget, '_profile', object()):
                        self.assertFalse(marker._refusal_possible_v38(reader, budget, context))
                    with mock.patch.object(budget, '_session_profile', core.FORMAL_SESSION_PROFILE):
                        self.assertFalse(marker._refusal_possible_v38(reader, budget, context))
                    malformed_counts = [list(row) for row in budget._used]
                    malformed_counts[0][0] = True
                    with mock.patch.object(budget, '_used', malformed_counts):
                        self.assertFalse(marker._refusal_possible_v38(reader, budget, context))
                    foreign_property_calls = []
                    class ForeignStore:
                        @property
                        def _session_profile_original_v28(self):
                            foreign_property_calls.append('profile')
                            raise AssertionError('foreign profile property accessed')
                    with mock.patch.object(budget, '_store', ForeignStore()):
                        self.assertFalse(marker._refusal_possible_v38(reader, budget, context))
                    self.assertEqual(foreign_property_calls, [])
                after = costs(marker)
                self.assertEqual(after['possible_false'] - before['possible_false'], 9)
                for key in ('possible_true', 'owner_calls', 'reader_facts_calls', 'accounting_facts_calls'):
                    self.assertEqual(after[key], before[key])
                self.assertEqual(tuple(reader._history), history)
                self.assertEqual(tuple(probe_fs.opens), opens)
                self.assertEqual(budget.status()['counts'], native_count)
                self.assertIsNone(marker._binding_refusal_v36)
                self.assertFalse(probe._unknown)
                self.assertFalse(marker._binding_ticket.unknown)
            finally: probe.close()
            # Every negative has a fresh actual Store/binding; no old unknown
            # flag is reset or erased to make a later case pass.
            for case in ('foreign_same_code', 'reader', 'worker', 'epoch', 'lock_scope', 'expired', 'already_unknown'):
                with self.subTest(refusal_case=case):
                    victim, victim_locks, unused_record, victim_io, unused_fs = make_store()
                    try:
                        consume_original_available_generations(victim)
                        marker = victim._marker
                        if case == 'already_unknown':
                            victim._unknown = True  # Explicit pre-existing-unknown HOST input.
                            with self.assertRaises(pending.PendingError):
                                victim._binding.verify(victim._coordination, victim._epoch)
                            self.assertTrue(victim._unknown)
                            self.assertFalse(marker._binding_ticket.ready)
                            self.assertTrue(marker._binding_ticket.unknown)
                            self.assertIsNone(marker._binding_refusal_v36)
                            continue
                        original = fail_binding(victim, victim._coordination)
                        row = marker._binding_refusal_v36
                        with victim._mutex, ExitStack() as negative:
                            if case == 'foreign_same_code': candidate = budgets.ResourceBudgetError('safe_exhaustion')
                            else: candidate = original
                            if case == 'reader': marker._reader = proc.ProcReader(_fs=proc_helpers.FakeFs(), _clock=victim_io.clock)
                            elif case == 'worker':
                                other = threading.Thread(target=lambda: None)  # Never started.
                                negative.enter_context(mock.patch.object(pending, 'threading',
                                    types.SimpleNamespace(current_thread=lambda: other)))
                            elif case == 'epoch': victim._epoch = object()
                            elif case == 'lock_scope': marker._locks = object()
                            elif case == 'expired': victim_io.clock.value = row.deadline
                            self.assertFalse(marker._consume_refusal_coord_v36(candidate, victim._coordination, victim._epoch))
                            self.assertFalse(marker._consume_refusal_store_v36(candidate, victim))
                            with self.assertRaises(coord.CoordinationError) as wrapped:
                                victim._coordination._report(candidate)
                            deny_business(victim, lambda: victim._report(wrapped.exception))
                            self.assertFalse(row.coord_seen); self.assertFalse(row.store_seen)
                            self.assertTrue(victim._unknown)
                    finally: victim.close()

            # Same-code failures AFTER native generation/FD IO are not a
            # before-generation refusal, even if the physical model FD closes.
            late, late_locks, unused_record, unused_io, late_fs = make_store()
            try:
                before = len(late._proc_reader._history), len(late_fs.opens)
                read_failure = budgets.ResourceBudgetError('safe_exhaustion')
                late_fs.read_error = read_failure  # Explicit post-open failing FakeFs seam.
                deny_business(late, lambda: late.current(late_locks))
                self.assertGreater(len(late._proc_reader._history), before[0])
                self.assertGreater(len(late_fs.opens), before[1])
                self.assertIsNone(late._marker._binding_refusal_v36)
                self.assertTrue(late._marker._binding_ticket.unknown)
                self.assertFalse(late._marker._binding_ticket.ready)
                # Content/identity is unknown, but the original native finally
                # closed the modeled FD once and immediately observed EBADF.
                # Physical inventory closure is not semantic identity/ready,
                # a before-generation refusal, or a restore/CloseProof.
                reader = late._proc_reader
                generation = reader._history[-1]
                self.assertTrue(reader.owns_generation(generation))
                self.assertIs(generation.error, read_failure)
                self.assertIs(type(generation.observation), proc.ProcObservation)
                self.assertEqual(generation.observation.kind, 'unknown')
                self.assertEqual(generation.observation.reason, 'unexpected_read_error')
                self.assertIsNone(generation.observation.actor)
                self.assertFalse(generation.observation.resource_pending)
                self.assertTrue(generation.ended)
                self.assertFalse(generation.active)
                self.assertFalse(generation.unknown)
                self.assertFalse(generation.late)
                self.assertEqual(len(generation.tickets), 1)  # First boot read aborts the pass.
                ticket = generation.tickets[0]
                self.assertTrue(reader.owns_open_ticket(ticket))
                self.assertIs(ticket.error, read_failure)
                self.assertTrue(ticket.returned)
                self.assertTrue(ticket.registered)
                self.assertTrue(ticket.close_attempted)
                self.assertTrue(ticket.close_returned)
                self.assertIsNone(ticket.close_result)
                self.assertTrue(ticket.ebadf_observed)
                self.assertIs(type(ticket.ebadf_errno), int)
                self.assertEqual(ticket.ebadf_errno, proc.errno.EBADF)
                self.assertIsInstance(ticket.ebadf_error, OSError)
                self.assertIsNone(ticket.close_error)
                self.assertFalse(ticket.unknown)
                self.assertEqual(late_fs.closed.count(ticket.descriptor), 1)
                self.assertNotIn(ticket.descriptor, late_fs.live)
                self.assertTrue(reader.closed_open_ticket(ticket))
                self.assertFalse(reader._pending)
                self.assertTrue(reader.history_closed())
                self.assertTrue(late._unknown)
            finally: late.close()


if __name__ == '__main__': unittest.main()
